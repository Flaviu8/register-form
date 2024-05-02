const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/User');

// Register a new user
const register = async (req, res, next) => {
  const {firstName, lastName, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, email, password: hashedPassword });
    await user.save();
    res.json({ message: 'Registration successful' });
  } catch (error) {
    next(error);
  }
};

// Login with an existing user
const login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const passwordMatch = bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Incorrect password' });
    } else {
      console.log('Succesfully logged in')
      
    }

    const token = jwt.sign({ userId: user._id }, process.env.SECRET_KEY, {
      expiresIn: '1 hour'
    });
    res.cookie('jwt',token, { httpOnly: true, secure: false, maxAge: 3600000 })
    res.json( `Welcome ${email}`);
  } catch (error) {
    next(error);
  }
};

const logout = async (req,res, next) => {
 
  let tokens = req.headers?.cookie;
  let token = tokens.split('=')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
    const user = await User.findById(decodedToken.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
      // Clear the JWT cookie from the client side
      res.clearCookie('jwt');
      res.status(200).json({ message: 'Logout successful' });
  
} catch (error) {
  next(error);
}

}

module.exports = { register, login, logout };