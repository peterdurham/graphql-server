require("dotenv").config();
const {
  ApolloServer,
  gql,
  AuthenticationError,
  UserInputError,
} = require("apollo-server");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("./models/User");
const validateRegisterInput = require("./validation/register");
const validateLoginInput = require("./validation/login");

const typeDefs = gql`
  type User {
    id: ID!
    email: String!
  }

  type Token {
    token: String!
  }

  type Query {
    me: User
    users: [User!]
  }

  type Mutation {
    registerUser(email: String!, password: String!): Token!
    loginUser(email: String!, password: String!): Token!
  }
`;

const getUser = async (auth) => {
  if (!auth) throw new AuthenticationError("you must be logged in!");

  const token = auth.split("Bearer ")[1];
  if (!token) throw new AuthenticationError("you should provide a token!");

  const user = await jwt.verify(token, process.env.SECRET, (err, decoded) => {
    if (err) throw new AuthenticationError("invalid token!");
    return decoded;
  });

  return user;
};

const getToken = ({ id, email }) =>
  jwt.sign(
    {
      id,
      email,
    },
    process.env.SECRET,
    { expiresIn: "1d" }
  );

const resolvers = {
  Query: {
    me: async (_, args, ctx) => {
      const user = await User.findOne({ _id: ctx.user.id });

      return {
        id: user._id,
        email: user.email,
      };
    },
    users: async () => {
      const users = await User.find();
      return users;
    },
  },
  Mutation: {
    registerUser: async (_, { email, password }) => {
      const { errors, valid } = validateRegisterInput({ email, password });
      if (!valid) throw new UserInputError("Error", { errors });

      const user = await User.findOne({ email });
      if (user)
        throw new UserInputError("A user with this email already exists");

      password = await bcrypt.hash(password, 10);
      const newUser = new User({
        email,
        password,
      });

      const res = await newUser.save();
      const token = getToken(res);
      return { token };
    },
    loginUser: async (_, { email, password }, ctx) => {
      const { errors, valid } = validateLoginInput({ email, password });
      if (!valid) throw new UserInputError("Error", { errors });

      const user = await User.findOne({ email });
      if (!user) throw new AuthenticationError("This user was not found");

      const match = await bcrypt.compare(password, user.password);
      if (!match) throw new AuthenticationError("Incorrect password");

      const token = getToken(user);
      return { token };
    },
  },
};

mongoose.connect(process.env.MONGOURL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: async ({ req }) => {
    const auth = req.headers.authorization || "";
    const user = await getUser(auth);

    return {
      user,
    };
  },
});
server.listen({ port: process.env.PORT || 4000 }).then(({ url }) => {
  console.log(`🚀 app running at ${url}`);
});
