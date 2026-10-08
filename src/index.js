import { Hono } from 'hono'
import { cors } from 'hono/cors'
import bcrypt from 'bcryptjs'

const app = new Hono()

app.use('*', cors())

app.use(async (c, next) => {
  if (c.req.path === "/get-sign") return next();

  const url = new URL(c.req.url);
  const sign = url.searchParams.get("sign");
  
  if (!sign || !await c.env.KV.get(sign)) {
    return c.json({ success: false, error: "Invalid sign" }, 403);
  }

  await next();
});


app.get("/get-sign", async (c) => {
  const sign = crypto.randomUUID();
  await c.env.KV.put(sign, "valid", {
    expirationTtl: 172800   
  });            
  return c.json({ success: true, sign });
});

app.get("/delete-sign", async (c) => {
  const url = new URL(c.req.url);
  const sign = url.searchParams.get("sign");
  if (sign) {
    await c.env.KV.delete(sign);
    return c.json({ success: true, message: "Sign deleted" });
  } else {
    return c.json({ success: false, error: "Sign is required" }, 400);
  }
});

app.put('/addUser', async (c) => {
  const body = await c.req.json()
  const { email, name, teamCode, Password, Role } = body

  if (!email || !name || !teamCode || !Password) {
    return c.json({ success: false, error: 'All fields are required' }, 400)
  }

  const checkUser = await c.env.DB.prepare(
    'SELECT * FROM Users WHERE Email = ?')
    .bind(email)
    .first();

  const teamCheck = await c.env.DB.prepare(
    'SELECT * FROM Teams WHERE "Team Code" = ?'
  ).bind(teamCode).first();

  if (checkUser) {
    return c.json({ success: false, error: 'User already exists' }, 409)
  }

  if (!teamCheck) {
    return c.json({ success: false, error: 'Team does not exist' }, 404)
  }

  const hashedPassword = await bcrypt.hash(Password, 10)

  const result = await c.env.DB.prepare(
    'INSERT INTO Users (Email, Name, "Team Code", Password, Role) VALUES (?, ?, ?, ?, ?)'
    )
    .bind(email, name, teamCode, hashedPassword, Role)
    .all();

  if (result.error) {
    return c.json({ success: false, error: 'Failed to add user' }, 500)
  }
  else{
    return c.json({ success: true, result })
  }
});

app.post('/getUser', async (c) => {
  const { email, Password } = await c.req.json();
  if (!email || !Password) {
    return c.json({ success: false, error: 'Email and Password are required' }, 400)
  }

  const pw = await c.env.DB.prepare(
    'SELECT * FROM Users WHERE Email = ?'
  ).bind(email).first();

  if (!pw) {
    return c.json({ error: 'User not found' }, 404)
  }

  const isValid = await bcrypt.compare(Password, pw.Password);

  if (!isValid) {
    return c.json({ success: false, error: 'Invalid password' }, 401)
  }
  else{
    const payload = {
      Email: email,
      TeamCode: pw['Team Code'],
      Name: pw.Name,
      Role: pw.Role,
      TimeTable: pw['Time Table']
    }

    return c.json({ success: true, message: 'User authenticated successfully', data: payload });
  }
});

app.post("/addTeam", async (c) => {
  const body = await c.req.json();
  const { teamCode, teamNum, teamName} = body;

  if (!teamCode || !teamNum || !teamName) {
    return c.json({ success: false, error: 'All fields are required' }, 400);
  }
  const result = await c.env.DB.prepare(
    'INSERT INTO Teams ("Team Code", "Number", "Name", "DataSetOne", "DataSetTwo", "DataSetThree", "DataSetFour", "DataSetFive", "DataSetSix", "DataSetSeven", "DataSetEight", "DataSetNine", "DataSetTen") VALUES (?, ?, ?, "", "", "", "", "", "", "", "", "", "")'
  ).bind(teamCode, teamNum, teamName).all();

  if (result.error) {
    return c.json({ success: false, error: 'Failed to add team' }, 500);
  } else {
    const check = await c.env.DB.prepare(
      'SELECT * FROM UnNamed WHERE "Team Number" = ?'
    ).bind(teamNum).first();
    if (check) {
      const input = await c.env.DB.prepare(
        `UPDATE Teams SET DataSetOne = ?, DataSetTwo = ?, DataSetThree = ?, DataSetFour = ?, DataSetFive = ?, DataSetSix = ?, DataSetSeven = ?, DataSetEight = ?, DataSetNine = ?, DataSetTen = ?, FinalNotes = ? WHERE Number = ?`
      ).bind(check["DataSetOne"], check["DataSetTwo"], check["DataSetThree"], check["DataSetFour"], check["DataSetFive"], check["DataSetSix"], check["DataSetSeven"], check["DataSetEight"], check["DataSetNine"], check["DataSetTen"], check["FinalNotes"],check["Team Number"]).run()
      
      if (!input.error){
        await c.env.DB.prepare(
          'DELETE FROM UnNamed WHERE "Team Number" = ?'
        ).bind(teamNum).run();
      }
      else{
        throw new Error(input.error);
      }
    }
    return c.json({ success: true, result });
  }
});

app.post('/getTeam', async (c) => {
  const { teamNum } = await c.req.json();

  if (!teamNum) {
    return c.json({ success: false, error: 'Team number is required' }, 400);
  }

  const team = await c.env.DB.prepare(
    'SELECT * FROM Teams WHERE Number = ?'
  ).bind(teamNum).first();

  if (!team) {
    const TEAM = await c.env.DB.prepare(
      'SELECT * FROM UnNamed WHERE "Team Number" = ?'
    ).bind(teamNum).first();
    if (!TEAM) {
      return c.json({ success: false, error: 'Team not found' }, 404);
    }
    return c.json({ success: true, team: TEAM, unNamed: true });
  }
  else{
    return c.json({ success: true, team, unNamed: false });
  }

});

function numberToWord(n) {
  const words = {
    1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five",
    6: "Six", 7: "Seven", 8: "Eight", 9: "Nine", 10: "Ten"
  };
  return words[n];
}

const ORDER = ["One","Two","Three","Four","Five","Six","Seven","Eight","Nine","Ten"];

const objectToListString = (obj) => {
  if (typeof obj !== "object" || obj === null) return obj;
  return Object.keys(obj).filter(k => obj[k]).join(", ");
};

const normalizeValue = (val) => {
  if (typeof val === "object" && val !== null) {
    return objectToListString(val);
  }
  return val;
};

const formatMultiValue = (val) => {
  if (Array.isArray(val)) return val;
  return [val];
};

app.post('/addReport', async (c) => {
  try {
    const body = await c.req.json();
    const { TeamNumber, FinalNotes } = body;

    if (!TeamNumber) throw new Error("TeamNumber is required");

    const datasetKeys = Object.keys(body)
      .filter(k => ORDER.includes(k))
      .sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b));

    let updateSets = [];
    let updateValues = [];

    let insertCols = [];
    let insertVals = [];

    datasetKeys.forEach((key, i) => {
      const entry = body[key];
      if (!Array.isArray(entry)) return;

      const [type, rawValue] = entry;
      const column = `DataSet${numberToWord(i + 1)}`;
      const value = normalizeValue(rawValue);

      switch (type) {
        case "text":
          updateSets.push(`${column} = ?`);
          updateValues.push(value);
          insertCols.push(column);
          insertVals.push(value);
          break;

        case "number":
          updateSets.push(`${column} = COALESCE(${column}, 0) + ?`);
          updateValues.push(value);
          insertCols.push(column);
          insertVals.push(value);
          break;

        case "avg":
          updateSets.push(`${column} = (COALESCE(${column}, 0) + ?) / 2`);
          updateValues.push(value);
          insertCols.push(column);
          insertVals.push(value);
          break;

        case "multi":
          updateSets.push(`${column} = ?`);
          updateValues.push(null);

          insertCols.push(column);
          insertVals.push(JSON.stringify(
            formatMultiValue(rawValue).reduce((acc, v, i) => {
              acc[i + 1] = normalizeValue(v);
              return acc;
            }, {})
          ));
          break;

        default:
          console.warn(`Unknown type "${type}" for ${column}`);
      }
    });

    // ---- FINAL NOTES HANDLING ----
    let newNotes = [];

    if (Array.isArray(FinalNotes)) {
      newNotes = FinalNotes.filter(n => n != null && n !== "");
    } else if (typeof FinalNotes === "string" && FinalNotes.trim() !== "") {
      newNotes = [FinalNotes.trim()];
    }

    if (newNotes.length === 0) newNotes = ["No Notes"];

    const tablesToCheck = ["Teams", "UnNamed"];

    for (const table of tablesToCheck) {
      const idCol = table === "Teams" ? "Number" : "Team Number";

      const row = await c.env.DB.prepare(
        `SELECT * FROM "${table}" WHERE "${idCol}" = ?`
      ).bind(TeamNumber).first();

      if (row) {
        // ---- HANDLE MULTI MERGING ----
        datasetKeys.forEach((key, i) => {
          const entry = body[key];
          if (!Array.isArray(entry)) return;

          const [type, rawValue] = entry;
          const column = `DataSet${numberToWord(i + 1)}`;

          if (type === "multi") {
            let prev = {};

            if (row[column]) {
              try { prev = JSON.parse(row[column]); } catch {}
            }

            const newValues = formatMultiValue(rawValue);
            const startIndex = Object.keys(prev).length;

            newValues.forEach((v, idx) => {
              prev[startIndex + idx + 1] = normalizeValue(v);
            });

            const mergedJson = JSON.stringify(prev);

            const idx = updateValues.findIndex(v => v === null);
            if (idx !== -1) {
              updateValues[idx] = mergedJson;
            }
          }
        });

        // ---- FINAL NOTES MERGE ----
        let prevNotes = {};
        if (row.FinalNotes) {
          try { prevNotes = JSON.parse(row.FinalNotes); } catch {}
        }

        const startIndex = Object.keys(prevNotes).length;

        newNotes.forEach((note, i) => {
          prevNotes[startIndex + i + 1] = note;
        });

        const finalNotesJson = JSON.stringify(prevNotes);

        updateSets.push(`FinalNotes = ?`);
        updateValues.push(finalNotesJson);
        updateValues.push(TeamNumber);

        const sql = `UPDATE "${table}" SET ${updateSets.join(", ")} WHERE "${idCol}" = ?`;

        const res = await c.env.DB.prepare(sql).bind(...updateValues).run();
        if (res.error) throw new Error(res.error);

        return c.json({ success: true, message: "Updated existing team" }, 200);
      }
    }

    // ---- INSERT NEW ROW ----
    const finalNotesJson = JSON.stringify(
      newNotes.reduce((acc, note, i) => {
        acc[i + 1] = note;
        return acc;
      }, {})
    );

    const insertColumns = ['"Team Number"', ...insertCols, '"FinalNotes"'];
    const placeholders = insertColumns.map(() => '?');
    const valuesToBind = [TeamNumber, ...insertVals, finalNotesJson];

    const insertSql = `INSERT INTO "UnNamed" (${insertColumns.join(", ")}) VALUES (${placeholders.join(", ")})`;

    const res = await c.env.DB.prepare(insertSql).bind(...valuesToBind).run();
    if (res.error) throw new Error(res.error);

    return c.json({ success: true, message: "Inserted new team" }, 200);

  } catch (err) {
    console.error(err);
    return c.json({ success: false, error: err.message || "Internal Error" }, 500);
  }
});

app.post("/getStatsOfTeam", async c => {
  const { teamNum } = await c.req.json();

  if (!teamNum) {
    return c.json({ success: false, error: 'Team number is required' }, 400);
  }

  const team = await c.env.DB.prepare(
    'SELECT * FROM Teams WHERE Number = ?'
  ).bind(teamNum).first();

  if (!team) {
    const TEAM = await c.env.DB.prepare(
      'SELECT * FROM UnNamed WHERE "Team Number" = ?'
    ).bind(teamNum).first();

    if (!TEAM) {
      return c.json({ success: false, error: 'Team has not data currently' }, 404);
    }

    const {DataSetOne, DataSetTwo, DataSetThree, DataSetFour, DataSetFive, DataSetSix, DataSetSeven, DataSetEight, DataSetNine, DataSetTen, FinalNotes} = TEAM;
    return c.json({ success: true,  DataSetOne: DataSetOne, DataSetTwo: DataSetTwo, DataSetThree: DataSetThree, DataSetFour: DataSetFour, DataSetFive: DataSetFive, DataSetSix: DataSetSix, DataSetSeven: DataSetSeven, DataSetEight: DataSetEight, DataSetNine: DataSetNine, DataSetTen: DataSetTen, FinalNotes: FinalNotes });
  }
  else{
    const {DataSetOne, DataSetTwo, DataSetThree, DataSetFour, DataSetFive, DataSetSix, DataSetSeven, DataSetEight, DataSetNine, DataSetTen, FinalNotes} = team;
    return c.json({ success: true,  DataSetOne: DataSetOne, DataSetTwo: DataSetTwo, DataSetThree: DataSetThree, DataSetFour: DataSetFour, DataSetFive: DataSetFive, DataSetSix: DataSetSix, DataSetSeven: DataSetSeven, DataSetEight: DataSetEight, DataSetNine: DataSetNine, DataSetTen: DataSetTen, FinalNotes: FinalNotes });
  }
});

app.post("getAllMembersOfTeamThatAreScoutersAndCaptains", async c => {
  const { teamCode } = await c.req.json();

  if (!teamCode) {
    return c.json({ success: false, error: 'Team code is required' }, 400);
  }

  const members = await c.env.DB.prepare(
    'SELECT Name, Email, Role, "Time Table" FROM Users WHERE "Team Code" = ? AND (Role = "Scouter" OR Role = "Captain")'
  ).bind(teamCode).all();

  if (!members || members.results.length === 0) {
    return c.json({ success: false, error: 'No members found for this team' }, 404);
  }

  return c.json({ success: true, members: members.results });
});

app.post("updateMemberTimeTable", async c => {
  const { Time, Date, Team, member } = await c.req.json();

  if (!Time || !Date || !Team || !member) {
    return c.json({ success: false, error: 'missing requirements' }, 400);
  }

  const timetable = JSON.stringify({ Time: Time, Date: Date, Team: Team });

  const res = await c.env.DB.prepare(
    'UPDATE Users SET "Time Table" = ? WHERE Name = ?'
  ).bind(timetable, member).run();

  if (res.error) {
    return c.json({ success: false, error: 'Internal Database Error' }, 500);
  } else{
    return c.json({ success: true, message: 'added new dataset(s)' }, 200);
  }
});

app.post("/updateMemberName", async c => {
  const { old: oldName, email, new: newName } = await c.req.json();

  if (!oldName || !email || !newName) {
    return c.json({ success: false, error: "missing requirements" }, 400);
  }

  try {
    const res = await c.env.DB.prepare(
      'UPDATE Users SET Name = ? WHERE Name = ? AND Email = ?'
    ).bind(newName, oldName, email).run();

    return c.json({ success: true, message: "Member name updated" }, 200);
  } catch (err) {
    return c.json({ success: false, error: "Internal Database Error" }, 500);
  }
});


app.post("/updateMemberPass", async c => {
  const { name, email, new: newPass } = await c.req.json();

  if (!name || !email || !newPass) {
    return c.json({ success: false, error: "missing requirements" }, 400);
  }

  try {
    const res = await c.env.DB.prepare(
      'UPDATE Users SET Password = ? WHERE Name = ? AND Email = ?'
    ).bind(bcrypt.hashSync(newPass, 10), name, email).run();

    return c.json({ success: true, message: "Member password updated" }, 200);
  } catch (err) {
    return c.json({ success: false, error: "Internal Database Error" }, 500);
  }
});


app.post("/updateMemberEmail", async c => {
  const { name, oldEmail, new: newEmail } = await c.req.json();

  if (!name || !oldEmail || !newEmail) {
    return c.json({ success: false, error: "missing requirements" }, 400);
  }

  try {
    const res = await c.env.DB.prepare(
      'UPDATE Users SET Email = ? WHERE Name = ? AND Email = ?'
    ).bind(newEmail, name, oldEmail).run();

    return c.json({ success: true, message: "Member email updated" }, 200);
  } catch (err) {
    return c.json({ success: false, error: "Internal Database Error" }, 500);
  }
});


app.post("/updateMemberTeam", async c => {
  const { old: oldTeamCode, new: newTeamCode, name, email } = await c.req.json();

  if (!oldTeamCode || !newTeamCode || !name || !email) {
    return c.json({ success: false, error: "missing requirements" }, 400);
  }

  try {
    const res = await c.env.DB.prepare(
      'UPDATE Users SET "Team Code" = ? WHERE "Team Code" = ? AND Name = ? AND Email = ?'
    ).bind(newTeamCode, oldTeamCode, name, email).run();

    return c.json({ success: true, message: "Member team updated" }, 200);
  } catch (err) {
    return c.json({ success: false, error: "Internal Database Error" }, 500);
  }
});

app.post("/updateMemberRole", async c => {
  const { email, name, old: oldRole, new: newRole } = await c.req.json();

  if (!name || !email || !oldRole || !newRole) {
    return c.json({ success: false, error: "missing requirements" }, 400);
  }

  try {
    const res = await c.env.DB.prepare(
      'UPDATE Users SET Role = ? WHERE Role = ? AND Name = ? AND Email = ?'
    ).bind(newRole, oldRole, name, email).run();

    return c.json({ success: true, message: "Member role updated" }, 200);
  } catch (err) {
    return c.json({ success: false, error: "Internal Database Error" }, 500);
  }
});

app.post("/deleteMember", async c => {
  const { name } = await c.req.json();   
  if (!name) {
    return c.json({ success: false, error: 'missing requirements' }, 400);
  }
  const res = await c.env.DB.prepare(
    'DELETE FROM Users WHERE Name = ?'
  ).bind(name).run();
  if (res.error) {
    return c.json({ success: false, error: 'Internal Database Error' }, 500);
  }
  else{
    return c.json({ success: true, message: 'Member deleted' }, 200);
  }
});

app.post("/updateTimeTable", async c => {
  const { name, teamCode, timetable } = await c.req.json();
  if (!name || !teamCode || !timetable) {
    return c.json({ success: false, error: 'missing requirements' }, 400);
  }
  const res = await c.env.DB.prepare(
    'UPDATE Users SET "Time Table" = ? WHERE Name = ? AND "Team Code" = ?'
  ).bind(JSON.stringify(timetable), name, teamCode).run();
  if (res.error) {
    return c.json({ success: false, error: 'Internal Database Error' }, 500);
  }
  else{
    return c.json({ success: true, message: 'Time table updated' }, 200);
  }
});

export default app;