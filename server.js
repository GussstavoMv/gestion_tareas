const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); 

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); 

const sequelize = new Sequelize('gestion_tareas', 'root', '', {
    host: 'localhost',
    dialect: 'mysql'
});


sequelize.authenticate()
    .then(() => console.log('Conexión a MySQL exitosa.'))
    .catch(err => console.error('Error conectando a MySQL:', err));


const User = sequelize.define('User', {
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false }
}, {
    tableName: 'users',
    timestamps: false 
});


const Task = sequelize.define('Task', {
    user_id: { type: DataTypes.INTEGER, allowNull: false },
    title: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.TEXT }
}, {
    tableName: 'tasks',
    timestamps: false
});


User.hasMany(Task, { foreignKey: 'user_id' });
Task.belongsTo(User, { foreignKey: 'user_id' });




app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ email, password: hashedPassword });
        res.status(201).send('Usuario creado exitosamente');
    } catch (error) {
        console.error(error);
        res.status(400).send('Error al registrar usuario');
    }
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(400).send('Usuario no encontrado');
        }

       
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).send('Contraseña incorrecta');
        }

        
        const token = jwt.sign({ id: user.id }, 'mi_clave_secreta_super_segura');
        res.json({ token });
    } catch (error) {
        res.status(500).send('Error en el servidor');
    }
});


const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).send('Acceso denegado. No hay token.');

    jwt.verify(token, 'mi_clave_secreta_super_segura', (err, user) => {
        if (err) return res.status(403).send('Token inválido.');
        req.user = user; 
        next(); 
    });
};



app.get('/api/tareas', verificarToken, async (req, res) => {
    try {
        const tareas = await Task.findAll({ where: { user_id: req.user.id } });
        res.json(tareas);
    } catch (error) {
        res.status(500).send('Error al obtener tareas');
    }
});


app.post('/api/tareas', verificarToken, async (req, res) => {
    try {
        const { title, description } = req.body;
        const nuevaTarea = await Task.create({
            user_id: req.user.id,
            title,
            description
        });
        res.status(201).json(nuevaTarea);
    } catch (error) {
        res.status(500).send('Error al crear la tarea');
    }
});



app.listen(3000, () => {
    console.log('Servidor backend corriendo en http://localhost:3000');
});