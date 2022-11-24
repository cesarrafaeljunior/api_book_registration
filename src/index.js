import express from "express";
import { compare } from "bcryptjs";
import { hash } from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 } from "uuid";
import { users } from "./database";

const app = express();
app.use(express.json());
const port = 3000;

const createUserController = async (req, res) => {
  const [status, user] = await createUserService(req.body);

  return res.status(status).json(user);
};

const listUserController = (req, res) => {
  return res.status(200).json(users);
};

const createUserService = async ({ name, email, password }) => {
  const foundUser = users.find((user) => user.email === email);

  if (foundUser) {
    return [401, { message: "Email already exists" }];
  }

  const hashPassword = await hash(password, 10);

  const newUser = {
    id: v4(),
    name: name,
    email: email,
    password: hashPassword,
  };
  users.push(newUser);

  return [201, newUser];
};

const updateUserController = (req, res) => {
  const id = req.params.id;

  const [status, user] = updateUserService(req.body, id);
  return res.status(status).json(user);
};

const updateUserService = (reqUser, id) => {
  let findUser = users.find((user) => user.id === id);
  const userIndex = users.findIndex((user) => user.id === id);

  if (!findUser) {
    return [404, { message: "User not found!" }];
  }

  users.splice(userIndex, 1);

  const newUser = {
    ...findUser,
    ...reqUser,
  };

  users.push(newUser);
  return [200, newUser];
};

const deleteUserController = (req, res) => {
  const id = req.params.id;

  const [status] = deleteUserService(id);

  return res.status(status).json();
};

const deleteUserService = (id) => {
  const userIndex = users.findIndex((user) => user.id === id);

  if (userIndex == -1) {
    return [404, { messsage: "User not found!" }];
  }

  users.splice(userIndex, 1);

  return [204, {}];
};

const userLoginController = async (req, res) => {
  const { email, password } = req.body;

  const [status, user] = await userLoginService(email, password);

  return res.status(status).json(user);
};

const userLoginService = async (email, password) => {
  const user = users.find((elem) => elem.email === email);

  if (!user) {
    return [401, { message: "Invalid email or password!" }];
  }

  const passwordMatch = await compare(password, user.password);

  if (!passwordMatch) {
    return [401, { message: "Invalid email or password!" }];
  }

  const token = jwt.sign({ email }, "SECRET_KEY", {
    expiresIn: "24h",
    subject: user.id,
  });

  const userRes = {
    ...user,
    token: token,
  };

  return [200, userRes];
};

const authMidlleware = (req, res, next) => {
  const authToken = req.headers.authorization;

  if (!authToken) {
    return res.status(401).json({ message: "Missing authorization!" });
  }

  const token = authToken.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decode) => {
    if (error) {
      return res.status(401).json({ message: "Invalid Token" });
    }

    return next();
  });
};

app.post("/users", createUserController);
app.post("/users/login", userLoginController);
app.get("/users", listUserController);
app.patch("/users/:id", authMidlleware, updateUserController);
app.delete("/users/:id", authMidlleware, deleteUserController);

app.listen(port, () => {
  console.log("Servidor rodando na porta " + port);
});
