const express = require("express");
const cors = require("cors");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Si un endpoint falla, responde el error en vez de tumbar el servidor
["get", "post", "patch", "delete"].forEach(m => {
  const orig = app[m].bind(app);
  app[m] = (p, ...hs) => orig(p, ...hs.map(f => (req, res, next) =>
    Promise.resolve(f(req, res, next)).catch(e => {
      console.log("❌", e.message);
      res.status(500).json({ error: String(e.message).slice(0, 300) });
    })));
});

const SECRET = process.env.JWT_SECRET || "cambia-este-secreto";

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ Conectado a MongoDB"))
  .catch(err => console.log("❌ Error:", err.message));

// ---------- MODELOS ----------
const Usuario = mongoose.model("Usuario", new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
}));

const Mascota = mongoose.model("Mascota", new mongoose.Schema({
  dueno: { type: String, required: true },
  nombre: { type: String, required: true },
  especie: { type: String, default: "Perro" },
  raza: String,
  edad: Number,
  historial: [{ tipo: String, texto: String, fecha: { type: Date, default: Date.now } }]
}));

const Cita = mongoose.model("Cita", new mongoose.Schema({
  dueno: { type: String, required: true },
  mascota: { type: mongoose.Schema.Types.ObjectId, ref: "Mascota", required: true },
  motivo: { type: String, enum: ["vacuna", "consulta", "baño", "otro"], default: "consulta" },
  cuando: { type: Date, required: true },
  estado: { type: String, enum: ["pendiente", "confirmada", "cancelada"], default: "pendiente" }
}));

const Registro = mongoose.model("Registro", new mongoose.Schema({
  usuario: String, accion: String, detalle: String, ip: String,
  fecha: { type: Date, default: Date.now }
}));
const log = (req, usuario, accion, detalle = "") =>
  new Registro({ usuario, accion, detalle, ip: req.headers["x-forwarded-for"] || req.ip })
    .save().catch(() => {});

// ---------- AUTH ----------
function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try { req.user = jwt.verify(token, SECRET).username; next(); }
  catch { res.status(401).json({ error: "No autorizado" }); }
}

app.post("/registro", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Faltan datos" });
  if (await Usuario.findOne({ username })) return res.status(409).json({ error: "Usuario ya existe" });
  await new Usuario({ username, password: await bcrypt.hash(password, 10) }).save();
  log(req, username, "registro");
  res.json({ ok: true });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await Usuario.findOne({ username });
  if (!user || !(await bcrypt.compare(password || "", user.password))) {
    log(req, username, "login_fallido");
    return res.status(401).json({ error: "Credenciales incorrectas" });
  }
  log(req, username, "login");
  res.json({ ok: true, username, token: jwt.sign({ username }, SECRET, { expiresIn: "8h" }) });
});

// ---------- MASCOTAS (cada usuario solo ve las suyas) ----------
app.get("/mascotas", auth, async (req, res) => {
  res.json((await Mascota.find({ dueno: req.user })).sort((a, b) => a.nombre.localeCompare(b.nombre)));
});

app.post("/mascotas", auth, async (req, res) => {
  const { nombre, especie, raza, edad } = req.body;
  if (!nombre) return res.status(400).json({ error: "El nombre es obligatorio" });
  const m = await new Mascota({ dueno: req.user, nombre, especie, raza, edad }).save();
  log(req, req.user, "crear_mascota", nombre);
  res.json(m);
});

app.delete("/mascotas/:id", auth, async (req, res) => {
  const m = await Mascota.findOneAndDelete({ _id: req.params.id, dueno: req.user });
  if (!m) return res.status(404).json({ error: "No existe" });
  await Cita.deleteMany({ mascota: m._id });
  log(req, req.user, "eliminar_mascota", m.nombre);
  res.json({ ok: true });
});

// ---------- HISTORIAL (vacunas y notas) ----------
app.post("/mascotas/:id/historial", auth, async (req, res) => {
  const { tipo, texto } = req.body;
  if (!texto) return res.status(400).json({ error: "Falta el texto" });
  const m = await Mascota.findOne({ _id: req.params.id, dueno: req.user });
  if (!m) return res.status(404).json({ error: "No existe" });
  m.historial.push({ tipo: tipo === "vacuna" ? "vacuna" : "nota", texto });
  await m.save();
  log(req, req.user, "historial_" + (tipo || "nota"), m.nombre);
  res.json(m);
});

// ---------- CITAS ----------
app.get("/citas", auth, async (req, res) => {
  res.json((await Cita.find({ dueno: req.user })).sort((a, b) => a.cuando - b.cuando));
});

app.post("/citas", auth, async (req, res) => {
  const { mascota, motivo, cuando } = req.body;
  if (!mascota || !cuando) return res.status(400).json({ error: "Faltan datos" });
  const m = await Mascota.findOne({ _id: mascota, dueno: req.user });
  if (!m) return res.status(404).json({ error: "Mascota no encontrada" });
  const c = await new Cita({ dueno: req.user, mascota, motivo, cuando }).save();
  log(req, req.user, "crear_cita", m.nombre + " - " + (motivo || "consulta"));
  res.json(c);
});

app.patch("/citas/:id", auth, async (req, res) => {
  const c = await Cita.findOneAndUpdate({ _id: req.params.id, dueno: req.user },
    { estado: req.body.estado }, { new: true, runValidators: true });
  if (!c) return res.status(404).json({ error: "No existe" });
  log(req, req.user, "cita_" + c.estado);
  res.json(c);
});

app.delete("/citas/:id", auth, async (req, res) => {
  await Cita.findOneAndDelete({ _id: req.params.id, dueno: req.user });
  log(req, req.user, "eliminar_cita");
  res.json({ ok: true });
});

// ---------- REGISTRO DE ACTIVIDAD (solo el propio) ----------
app.get("/registros", auth, async (req, res) => {
  res.json((await Registro.find({ usuario: req.user })).sort((a, b) => b.fecha - a.fecha).slice(0, 50));
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Servidor corriendo en puerto " + port));
