require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const { Sequelize, DataTypes } = require('sequelize');


// Middlewares
app.use(cors());
app.use(express.json());

// Configurações
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET;

// Conexão com Banco
const sequelize = new Sequelize(
  process.env.MYSQLDATABASE,
  process.env.MYSQLUSER,
  process.env.MYSQLPASSWORD,
  {
    host: process.env.MYSQLHOST,
    port: parseInt(process.env.MYSQLPORT),
    dialect: 'mysql',
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    }
  }
);




// Modelo
const User = sequelize.define('user', {
  nome: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  senha: {
    type: DataTypes.STRING,
    allowNull: false,
  },
}, {
  freezeTableName: true, // Evita pluralização do nome da tabela
});

// Sincronizar Banco
sequelize
  .sync()
  .then(() => console.log('Banco de dados conectado e tabelas sincronizadas'))
  .catch((err) => console.error('Erro ao conectar:', err));

// Middleware de autenticação
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ mensagem: 'Token não fornecido!' });
  }

  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ mensagem: 'Token inválido!' });
    }

    req.user = user; // Dados do usuário no request
    next();
  });
}

// ROTAS

// Cadastro de usuário
app.post('/usuarios', async (req, res) => {
    console.log('Requisição recebida:', req.body); // Adicione este log
    try {
      const { nome, email, senha } = req.body;
  
      if (!nome || !email || !senha) {
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
      }
  
      const saltRounds = 10;
      const senhaHash = await bcrypt.hash(senha, saltRounds);
  
      const user = await User.create({ nome, email, senha: senhaHash });
      res.status(201).json({ mensagem: 'Usuário criado!', user });
    } catch (error) {
      console.error('Erro na criação do usuário:', error); // Adicione este log
      res.status(400).json({ erro: error.message });
    }
  });

// Login de usuário
app.post('/login', async (req, res) => {
  try {
    console.log('Requisição recebida:', req.body); // Log para depuração
    const { email, senha } = req.body;

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ mensagem: 'Usuário não encontrado' });
    }

    const senhaCorreta = await bcrypt.compare(senha, user.senha);

    if (!senhaCorreta) {
      return res.status(401).json({ mensagem: 'Senha inválida' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      SECRET,
      { expiresIn: '1h' }
    );

    res.json({ mensagem: 'Login realizado com sucesso!', token });
  } catch (error) {
    console.error('Erro no login:', error); // Log para depuração
    res.status(400).json({ erro: error.message });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

