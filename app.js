//Install Command:
//npm init -y
//npm i express express-handlebars body-parser express-session mongodb mongoose bcrypt connect-mongodb-session

//Before going into code:
// - Be sure to start the database before use.
//#sudo systemcl start mongodb
//#sudo system status mongodb
// - Open Mongo Compass to view the database

const express = require('express');
const server = express();

const bodyParser = require('body-parser');
server.use(express.json()); 
server.use(express.urlencoded({ extended: true }));

const handlebars = require('express-handlebars');
server.set('view engine', 'hbs');
server.engine('hbs', handlebars.engine({
    extname: 'hbs',
}));

server.use(express.static('public'));

//Require a MongoDB connection. This will create a client
//to connect to the specified mongoDB. The last part of the
//URL is the database it connects to.
const { MongoClient, ObjectId } = require('mongodb');

// const { MongoClient } = require('mongodb');
const databaseURL = "mongodb+srv://ccapdev:p17BE1a4NBH53Tfk@webapplicationgroup7.hnqoatv.mongodb.net/WebApplicationGroup7?retryWrites=true&w=majority&appName=WebapplicationGroup7";
const mongoClient = new MongoClient(databaseURL);

const databaseName = "logindb"; //name of the login database
const collectionName = "login";
const postsCollectionName = "posts"; 
const commentsCollectionName = "comments";
const profilesCollectionName = "profiles";
const userVotesCollectionName = 'userVotes'; 

//To interact with the mongo database, a client needs to be made
//and then the client should connect to the database.
async function initialConntection(){
    let con = await mongoClient.connect();
    console.log("Attempt to create!");
    const dbo = mongoClient.db(databaseName);
    //Will create a collection if it has not yet been made
    dbo.createCollection(collectionName);
    dbo.createCollection(postsCollectionName);
    dbo.createCollection(commentsCollectionName);
    dbo.createCollection(profilesCollectionName);
    dbo.createCollection(userVotesCollectionName);
  }
initialConntection();

const session = require('express-session');
const MongoStore = require('connect-mongodb-session')(session);
const bcrypt = require('bcrypt');

const store = new MongoStore({
  uri: databaseURL,
  databaseName: databaseName,
  collection: 'mySession',
  expires: 3 * 7 * 24 * 60 * 60 * 1000 // 3 weeks in milliseconds
});

server.use(session({
  secret: 'a secret fruit',
  saveUninitialized: true, 
  resave: false,
  store: store
}));
/*
const mongoose = require('mongoose');
mongoose.connect('mongodb://127.0.0.1:27017/logindb');

const postSchema = new mongoose.Schema({
    title: { type: String },
    image: { type: String }
},{ versionKey: false });
  
const postModel = mongoose.model('post', postSchema);

const profileSchema = new mongoose.Schema({
    image: { type: String },
    name: { type: String },
    bio: { type: String }
},{ versionKey: false });
  
const profileModel = mongoose.model('profile', profileSchema);

const commentSchema = new mongoose.Schema({
    title: { type: String },
    comment: { type: String }
},{ versionKey: false });
  
const commentModel = mongoose.model('comment', commentSchema);
*/
//If there are no initial functions to be called, just call the
//connect function.
//mongoClient.connect();

const isAuthenticated = require('./auth');
let currentUser = ''; //will be used for the knowing which user is logged in

server.get('/', function(req, resp){
  resp.render('login-page',{
    layout: 'loginindex',
    title: 'Login Page'
  });
});

server.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/');
  });
});

server.get('/aboutpage', (req, resp) => {
  resp.render('about-page',{
    layout: 'aboutpageindex',
    title: 'About Page'
  });
});

//This is the login function. It uses the logindb database and compares it to the input.
server.post('/read-user', isAuthenticated, async function(req, resp) {
  const dbo = mongoClient.db(databaseName);
  const loginCollection = dbo.collection(collectionName);
  const commentsCollection = dbo.collection(commentsCollectionName);
  const col = dbo.collection(postsCollectionName);
  const posts = await col.find({deleted: false}).toArray();
  const votes = dbo.collection(userVotesCollectionName);

  // A search query will come in the form of a JSON array as well. Make
  // sure that it follows the correct syntax.
  const searchQuery = { user: req.body.user};
  
  let user = await loginCollection.findOne(searchQuery);
  
  console.log('Finding user');
  console.log('Inside: ' + JSON.stringify(user));

  if (user != null) {  // If login credentials are correct, it will go to the main page, FOR NOW THOUGH, it will go to the view post page.
      const isPasswordValid = await bcrypt.compare(req.body.pass, user.pass); // Compare hashed passwords
      if (isPasswordValid) {
        let commentsCursor = commentsCollection.find({deleted: false});
        let comments = await commentsCursor.toArray();
        const votesCol = dbo.collection(userVotesCollectionName);
        const userVotes = await votesCol.find({ userId: currentUser }).toArray();
        const votedPosts = new Set(userVotes.map(vote => vote.postId.toString()));
        req.session.login_user = user;
        req.session.login_id = req.sessionID;
        currentUser = req.body.user;

        resp.render('MainPage', {
          layout: 'MainPageindex',
          title: 'Main Page',
          posts: posts, // Pass fetched posts to the template
          username: currentUser,
          votes: votedPosts
        });
      }else {  // If login credentials are incorrect, it will go to the login page
        resp.render('login-page', {
            layout: 'loginindex',
            title: 'Login Page'
        });
      }
  } else {  // If login credentials are incorrect, it will go to the login page
      resp.render('login-page', {
          layout: 'loginindex',
          title: 'Login Page'
      });
  }
});

server.get('/register-page', function(req, resp){
  resp.render('register-page',{
    layout: 'registerindex',
    title: 'Register Page'
  });
});

//It will implement check Register
server.post('/addUser', async (req, res) => {
  const dbo = mongoClient.db(databaseName);
  const col = dbo.collection(profilesCollectionName); // Assuming profiles collection stores user data
  const loginCollection = dbo.collection(collectionName);

  // Extract user data from request body
  const user = req.body.user;
  const password = req.body.pass;  // Consider hashing password before storing
  const confirmPassword = req.body.confirmpass;

  // Input validation (optional but recommended)
  if (!user || !password || !confirmPassword) {
    return res.render('register-page', {
      layout: 'registerindex',
      title: 'Register Page',
      errorMessage: 'Missing required fields: username, password, or confirm password'
    });
  } else if (password !== confirmPassword) {
    return res.render('register-page', {
      layout: 'registerindex',
      title: 'Register Page',
      errorMessage: 'Passwords do not match'
    });
  }

  // Check for existing username
  const searchQuery = { username: user };
  try {
    const existingUser = await col.findOne(searchQuery);
    if (existingUser) {
      return res.render('register-page', {
        layout: 'registerindex',
        title: 'Register Page',
        errorMessage: 'Username already exists!'
      }); // Conflict status code
    }
  } catch (error) {
    console.error('Error finding user:', error);
    return res.status(500).send('Server error');
  }
  

  // Hash the password before storing
  const saltRounds = 10; // Adjust salt rounds as needed (higher for more security)
  bcrypt.genSalt(saltRounds, async (err, salt) => {
    if (err) {
      console.error('Error generating salt:', err);
      return res.status(500).send('Server error');
    }

    try {
      const hash = await bcrypt.hash(password, salt);

      // Create new user objects with hashed password
      const newUser = {
        username: user,
        password: hash, // Store hashed password
        creation_date: new Date().toLocaleString(),
        deleted: false,
        description: null
      };

      const newUserAgain = {
        user: user,
        pass: hash, // Store hashed password
        creation_date: new Date().toLocaleString(),
        deleted: false,
        description: null
      };

      // Insert user data into collections
      await col.insertOne(newUser);
      await loginCollection.insertOne(newUserAgain);
      res.redirect('/'); // Redirect to main page after successful registration
    } catch (error) {
      console.error('Error adding user:', error);
      res.status(500).send('Error adding user');
    }
  });
});


server.get('/main', isAuthenticated, async (req, res) => {
  try {
      const dbo = mongoClient.db(databaseName);
      const col = dbo.collection(postsCollectionName);
      const votes = dbo.collection(userVotesCollectionName);

      // Fetch all posts where deleted is false
      const votedPosts = await votes.find({userId: currentUser}).toArray();
      const posts = await col.find({deleted: false}).toArray();

      // Render the MainPage.hbs template with posts data
      res.render('MainPage', {
          layout: 'MainPageindex',
          title: 'Main Page',
          posts: posts,  // Pass fetched posts to the template
          votes: votedPosts
      });
  } catch (error) {
      console.error('Error fetching posts:', error);
      res.status(500).send('Error fetching posts');
  }
});

server.get('/search', async (req, res) => {
  const query = req.query.q || '';
  const searchRegex = new RegExp(query, 'i'); // Case-insensitive search

  try {
      const dbo = mongoClient.db(databaseName);
      const postsCol = dbo.collection(postsCollectionName);

      const posts = await postsCol.find({
          $or: [
              { title: searchRegex },
              { description: searchRegex }
          ]
      }).toArray();

      res.render('search-results', { 
        layout:'searchindex',
        title: 'Search Results',
        posts: posts, 
        query: query }); // Render search results
  } catch (error) {
      console.error('Error fetching search results:', error);
      res.status(500).json({ error: 'Internal Server Error' });
  }
});

server.get('/addPostPage', isAuthenticated, (req, res) => {
  res.render('addpostpage', {
      layout: 'post-layout-index',
      title: 'Add Post Page',
  });
});

server.post('/posts/upvote/:postId', async (req, res) => {
  try {
    const dbo = mongoClient.db(databaseName);
    const postsCol = dbo.collection(postsCollectionName);
    const votesCol = dbo.collection(userVotesCollectionName);
    const postId = req.params.postId;
    const userId = currentUser; // Replace with actual user ID retrieval logic

    // Check if user has already voted
    const existingVote = await votesCol.findOne({ postId: new ObjectId(postId), userId: userId });

    if (existingVote) {
      if (existingVote.voteType === 'upvote') {
        // If already upvoted, remove the vote
        await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: -1 } });
        await votesCol.deleteOne({ _id: existingVote._id });
      } else {
        // Change from downvote to upvote
        await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: 2 } });
        await votesCol.updateOne({ _id: existingVote._id }, { $set: { voteType: 'upvote' } });
      }
    } else {
      // Add a new upvote
      await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: 1 } });
      await votesCol.insertOne({ userId: userId, postId: new ObjectId(postId), voteType: 'upvote' });
    }

    res.status(200).send('Post upvoted');
  } catch (error) {
    console.error('Error upvoting post:', error);
    res.status(500).send('Internal server error');
  }
});

server.post('/posts/downvote/:postId', async (req, res) => {
  try {
    const dbo = mongoClient.db(databaseName);
    const postsCol = dbo.collection(postsCollectionName);
    const votesCol = dbo.collection(userVotesCollectionName);
    const postId = req.params.postId;
    const userId = currentUser; // Replace with actual user ID retrieval logic

    // Check if user has already voted
    const existingVote = await votesCol.findOne({ postId: new ObjectId(postId), userId: userId });

    if (existingVote) {
      if (existingVote.voteType === 'downvote') {
        // If already downvoted, remove the vote
        await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: 1 } });
        await votesCol.deleteOne({ _id: existingVote._id });
      } else {
        // Change from upvote to downvote
        await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: -2 } });
        await votesCol.updateOne({ _id: existingVote._id }, { $set: { voteType: 'downvote' } });
      }
    } else {
      // Add a new downvote
      await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: -1 } });
      await votesCol.insertOne({ userId: userId, postId: new ObjectId(postId), voteType: 'downvote' });
    }

    res.status(200).send('Post downvoted');
  } catch (error) {
    console.error('Error downvoting post:', error);
    res.status(500).send('Internal server error');
  }
});

server.post('/addPost', isAuthenticated, async (req, res) => {
  const dbo = mongoClient.db(databaseName);
  const col = dbo.collection(postsCollectionName);

  const newPost = {
      _id: new ObjectId(), // Generate a new unique ObjectId for each post
      username: currentUser, // Replace with actual current user
      time: new Date().toLocaleString(),
      title: req.body.title,
      tag: req.body.community,
      description: req.body.body, 
      deleted : false // Set deleted to false by default 
  };

  try {
      await col.insertOne(newPost);
      res.redirect('/main'); // Redirect back to the main page after adding the post
  } catch (error) {
      console.error('Error adding post:', error);
      res.status(500).send('Error adding post');
  }
});

server.get('/view-post/view/:postId', isAuthenticated, async (req, resp) => {
  const dbo = mongoClient.db(databaseName);
  const col = dbo.collection(postsCollectionName);
  const postId = req.params.postId;
  const votesCol = dbo.collection(userVotesCollectionName);
  //Fetch all comments from the comments collection
  const commentsCollection = dbo.collection(commentsCollectionName);

  let commentsCursor = commentsCollection.find({ postNum: postId });
  let comments = await commentsCursor.toArray();
    // Fetch the specific post by its ID
    const post = await col.findOne({ _id: new ObjectId(postId) });
    const existingVote = await votesCol.findOne({ postId: new ObjectId(postId), userId: currentUser });

    resp.render('view-post-page', {
      layout: 'viewpostindex',
      title: 'View Post',
      post: post,
      comments: comments,
      username: req.body.username,
      votes: existingVote ? existingVote.voteType : 'none'
    });

    
    //console.log('Comments: ' + JSON.stringify(post));
});

// individual post upvote and downvote 
server.post('/view-post/view/:postId/vote', isAuthenticated, async (req, res) => {
  try {
    const dbo = mongoClient.db(databaseName);
    const postsCol = dbo.collection(postsCollectionName);
    const votesCol = dbo.collection(userVotesCollectionName);
    const postId = req.params.postId;
    const { voteType } = req.body; // "upvote" or "downvote"
    const userId = currentUser; // Replace with actual user ID retrieval logic

    // Determine the vote increment based on the voteType
    const voteIncrement = voteType === 'upvote' ? 1 : -1;
    const oppositeVoteType = voteType === 'upvote' ? 'downvote' : 'upvote';
    const voteIncrementOpposite = voteType === 'upvote' ? 2 : -2;

    // Check if user has already voted
    const existingVote = await votesCol.findOne({ postId: new ObjectId(postId), userId: userId });

    if (existingVote) {
      if (existingVote.voteType === voteType) {
        // If the vote type is the same, remove the vote
        await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: -voteIncrement } });
        await votesCol.deleteOne({ _id: existingVote._id });
      } else {
        // Change the vote type from the opposite to the current voteType
        await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: voteIncrementOpposite } });
        await votesCol.updateOne({ _id: existingVote._id }, { $set: { voteType: voteType } });
      }
    } else {
      // Add a new vote
      await postsCol.updateOne({ _id: new ObjectId(postId) }, { $inc: { votes: voteIncrement } });
      await votesCol.insertOne({ userId: userId, postId: new ObjectId(postId), voteType: voteType });
    }

    // Fetch the updated post to get the latest vote count
    const updatedPost = await postsCol.findOne({ _id: new ObjectId(postId) });

    res.status(200).json({ success: true, voteCount: updatedPost.votes });
  } catch (error) {
    console.error('Error processing vote:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

server.post('/create-comment/:postId', isAuthenticated, async function(req, resp) {
  const dbo = mongoClient.db(databaseName);
  const col = dbo.collection(commentsCollectionName);
  const col1 = dbo.collection(postsCollectionName);
  const postId = req.params.postId;

  // Get the comment and username from the request body
  const comment = {
      text: req.body.comment,
      username: currentUser,
      postNum: req.params.postId,
      createdAt: new Date().toLocaleString(),
      replies: [],
      deleted : false // Set deleted to false by default
  };

  //Insert the comment into the collection
  await col.insertOne(comment);
  console.log('Comment added: ' + JSON.stringify(comment));

  // Fetch updated comments
  let commentsCursor = col.find({ postNum: postId }); // Filter by postId
  let comments = await commentsCursor.toArray();

  // Fetch all posts from the 'posts' collection
  const post = await col1.findOne({ _id: new ObjectId(postId) });
  
  resp.render('view-post-page', {
    layout: 'viewpostindex',
    title: 'View Post',
    post: post,
    comments: comments,
    username: req.body.username
  });
  
});

server.post('/reply/:commentId/:postnum', isAuthenticated, async function(req, resp) {
  const dbo = mongoClient.db(databaseName);
  const col = dbo.collection(commentsCollectionName);
  const col1 = dbo.collection(postsCollectionName);
  const postnum = req.params.postnum;

  const commentId = req.params.commentId;

  const reply = {
    username: currentUser,
    text: req.body.comment,
    createdAt: new Date().toLocaleString()
  };

  // Update the comment to add the reply
  await col.updateOne(
    { _id: new ObjectId(commentId) },
    { $push: { replies: reply } }
  );

  //Insert the comment into the collection

  // Fetch updated comments
  let commentsCursor = col.find({ postNum: postnum}); // Filter by postId
  let comments = await commentsCursor.toArray();

  // Fetch all posts from the 'posts' collection
  const post = await col1.findOne({ _id: new ObjectId(postnum) });
  
  resp.render('view-post-page', {
    layout: 'viewpostindex',
    title: 'View Post',
    post: post,
    comments: comments,
    username: req.body.username
  });
  
});

// delete 
//needs revision for view post 
server.get('/view-post/delete/:postId', isAuthenticated, async (req, res) => {
  try {
    
      const dbo = mongoClient.db(databaseName);
      const col = dbo.collection(postsCollectionName);
      const postId = req.params.postId;
      // Find the post by ID
      const post = await col.findOne({ _id: new ObjectId(postId) });

      if (!post) {
          return res.status(404).send('Post not found');
      }

      // Check if the post's username matches the current user
      if (post.username !== currentUser) {
          return res.status(403).send('You do not have permission to delete this post');
      }

      // Mark the post as deleted
      const result = await col.updateOne(
          { _id: new ObjectId(postId) },
          { $set: { deleted: true } } // Set 'deleted' field to true
      );

      if (result.modifiedCount === 1) {
          res.status(200).send('Post marked as deleted');
      } else {
          res.status(500).send('Failed to mark post as deleted');
      }
  } catch (error) {
      console.error('Error marking post as deleted:', error);
      res.status(500).send('Internal server error');
  }
});

server.get('/viewUserProfile/delete/:postId', async (req, res) => {
    try {
        const dbo = mongoClient.db(databaseName);
        const col = dbo.collection(postsCollectionName);
        const postId = req.params.postId;

        // Find the post by ID
        const post = await col.findOne({ _id: new ObjectId(postId) });

        if (!post) {
            return res.status(404).send('Post not found');
        }

        // Check if the post's username matches the current user
        if (post.username !== currentUser) {
            return res.status(403).send('You do not have permission to delete this post');
        }

        // Mark the post as deleted
        const result = await col.updateOne(
            { _id: new ObjectId(postId) },
            { $set: { deleted: true } }
        );

        if (result.modifiedCount === 1) {
            res.status(200).send('Post marked as deleted');
        } else {
            res.status(500).send('Failed to mark post as deleted');
        }
    } catch (error) {
        console.error('Error marking post as deleted:', error);
        res.status(500).send('Internal server error');
    }
});


server.get('/viewUserProfile', isAuthenticated, async function(req, resp){

  const dbo = mongoClient.db(databaseName);
  const pro = dbo.collection(profilesCollectionName);
  const pos = dbo.collection(postsCollectionName);

  // Search query for the user's profile
  const searchQuery = { username: currentUser };
  
  try {
    // Fetch the user's profile
    let Pval = await pro.findOne(searchQuery);

    if (!Pval) {
      return resp.status(404).send('User profile not found');
    }

    // Fetch the user's posts that are not marked as deleted
    const cursor2 = pos.find({ username: currentUser, deleted: false });
    let Pvals = await cursor2.toArray();

    console.log('Finding user');
    console.log('Inside: ' + JSON.stringify(Pval));

    resp.render('viewUser_post', {
      layout: 'index2',
      title: 'User Profile',
      user: Pval,
      post: Pvals
    });
  } catch (error) {
    console.error('Error fetching user profile or posts:', error);
    resp.status(500).send('Internal server error');
  }
});



server.get('/viewUser_Com', async function(req, resp){
  const dbo = mongoClient.db(databaseName);
  const pro = dbo.collection(profilesCollectionName);
  const com = dbo.collection(commentsCollectionName);
  //A search query will come in the form of a JSon array as well. Make
  //sure that it follows the correct syntax.
  const searchQuery = { username: currentUser};
  
  let Pval = await pro.findOne(searchQuery);

  const cursor2 = com.find(searchQuery);
  let Cvals = await cursor2.toArray();

  console.log('Finding user');
  console.log('Inside: ' + JSON.stringify(Pval));

  resp.render('viewUser_com',{
      layout: 'index',
      title: 'User Profile',
      user: Pval,
      comment: Cvals
  });
});




server.get('/edit_profile', isAuthenticated, function(req, resp){
  resp.render('editProfile',{
      layout: 'index5',
      title: 'Edit User Profile'
  });
});



//-----------------------------------------------------------------------


const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Console } = require('console');

// Set up Multer for file uploads
const storage = multer.memoryStorage(); // Use memory storage to access file buffer directly

const upload = multer({ storage: storage });



const computeFileHash = (fileBuffer) => {
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
};


// Handle file upload and render the image
server.post('/upload', upload.single('profileImage'), (req, res) => {
  if (req.file) {
    const fileHash = computeFileHash(req.file.buffer);
    const fileExtension = path.extname(req.file.originalname);
    const fileName = `${fileHash}${fileExtension}`;
    const filePath = path.join('public', 'uploads', fileName);

    // Check if the file already exists
    if (fs.existsSync(filePath)) {
      res.render('editProfile', { imageUrl: `/uploads/${fileName}`, layout: 'index5' });
    } else {
      // Save the new file
      fs.writeFile(filePath, req.file.buffer, (err) => {
        if (err) {
          res.send('File upload failed');
        } else {
          res.render('editProfile', { imageUrl: `/uploads/${fileName}`, layout: 'index5'});
        }
      });
    }
  } else {
    res.send('No file uploaded');
  }
});



//-----------------------------------------------------------------------


//Future Use for File Upload

/*


const multer = require('multer');
const path = require('path');

// Set storage engine
const storage = multer.diskStorage({
  destination: './public/images/',
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

// Init upload
const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000 },
  fileFilter: function (req, file, cb) {
    checkFileType(file, cb);
  }
}).single('profileImage');

// Check file type
function checkFileType(file, cb) {
  // Allowed ext
  const filetypes = /jpeg|jpg|png|gif/;
  // Check ext
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  // Check mime
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Images Only!');
  }
}

// Handle file upload and save
server.post('/upload1', (req, res) => {
  res.render('editProfile', {
    msg: 'File uploaded!',
    file: `images/${req.file.profileImage}`
  });
});


*/


server.post('/delete_profile', async (req, res) => {
  const dbo = mongoClient.db(databaseName);
  const pro = dbo.collection(profilesCollectionName);
  const loginCollection = dbo.collection(collectionName);
  const post = dbo.collection(postsCollectionName);
  const comm =  dbo.collection(commentsCollectionName);

  const updatedelete = {$set: {username: "<delete>"}};

  const user1 = req.body.User1;
  const user = await loginCollection.findOne({ user: user1 });
  await loginCollection.deleteOne({ _id: user._id });
  await comm.updateMany({ username: user1 }, updatedelete);
  await post.updateMany({ username: user1 }, updatedelete);
  
  res.redirect('/');

});



server.post('/update-user', async function(req, resp){
  const dbo = mongoClient.db(databaseName);
  const pro = dbo.collection(profilesCollectionName);
  const loginCollection = dbo.collection(collectionName);
  const post = dbo.collection(postsCollectionName);
  const comm =  dbo.collection(commentsCollectionName);


  //To update a query, it will need to have a search parameter and a
  //change of values.
  const updateQuery = { username: currentUser };
  const updateQuery2 = { user: currentUser };

  const updatename = {$set: {user: req.body.Uname}};
  const updateDoc1 = {
    $set: {
      username: req.body.Uname,
      image: req.body.profImage
    },
  };

  const updateDoc2 = {$set: {username: req.body.Uname}};
  const updateDoc3 = {$set: {image: req.body.profImage}};

  let res;
  let res2;
  let res3;
  let res4;

  //This function will only update a single entry.
  if (req.body.profImage && req.body.Uname){
    res = await pro.updateOne(updateQuery, updateDoc1);
    res2 = await loginCollection.updateOne(updateQuery2, updatename);
    res3 = await post.updateMany(updateQuery, updateDoc2);
    res4 = await comm.updateMany(updateQuery, updateDoc2);
    currentUser = req.body.Uname;
  }else if(!req.body.Uname){
    res = await pro.updateOne(updateQuery, updateDoc3);
  }else{
    res = await pro.updateOne(updateQuery, updateDoc2);
    res2 = await loginCollection.updateOne(updateQuery2, updatename);
    res3 = await post.updateMany(updateQuery, updateDoc2);
    res4 = await comm.updateMany(updateQuery, updateDoc2);
    currentUser = req.body.Uname;
  }
  

  console.log(req.body.Uname);
  console.log(req.body.profImage);
  console.log('Update successful');
  console.log('Inside: '+JSON.stringify(res));
  resp.redirect('/viewUserProfile');
  
});





server.post('/update-post', async function(req, resp) {
  const dbo = mongoClient.db(databaseName);
  const post = dbo.collection(postsCollectionName);

  const { OGTitle, TitleIn, BodyIn, option } = req.body;
  console.log('Request Body:', req.body);

  const updateQuery = { title: OGTitle };
  console.log(updateQuery);
  let updateDoc = {};

  // Construct the update document based on provided fields
  if (TitleIn) updateDoc['title'] = TitleIn;
  if (BodyIn) updateDoc['description'] = BodyIn;

  if(option && option !== "option1"){
    updateDoc['tag'] = option;
  }

  if (Object.keys(updateDoc).length === 0) {
    console.log('No fields to update.');
    return resp.redirect('/viewUserProfile');
  }

  // Perform the update
  let res = await post.updateOne(updateQuery, { $set: updateDoc });

  console.log('Post updated:', res);
  resp.redirect('/viewUserProfile');
});


// EDIT COMMENT
server.post('/edit-comments', async function(req, resp){
  const dbo = mongoClient.db(databaseName);
  const comment = dbo.collection(commentsCollectionName);

  const { prevCom, newCom } = req.body;
  console.log('Request Body:', req.body);

  // Looks for a text field that matches the previous comment
  const updateQuery = { text: prevCom };
  // Object to hold updated comment
  let updateDoc = {};
  
  // To replace previous comment
  if(newCom){
    updateDoc['text'] = newCom;
  }

  console.log('Update Query:', updateQuery);
  console.log('Update Doc:', updateDoc);
  
  // Check if there are any fields to update
  if(Object.keys(updateDoc).length === 0){
    console.log('No fields to update.');
    return resp.redirect('/viewUser_Com');
  }

  // Do the update
  let res = await comment.updateOne(updateQuery, { $set: updateDoc });

  // Redirect to user's profile
  resp.redirect('/viewUser_Com');
});


// DELETE COMMENT
server.post('/delete-comment', isAuthenticated, async function(req, res) {
  const dbo = mongoClient.db(databaseName);
  const comment = dbo.collection(commentsCollectionName);

  const { commentId } = req.body;

  try {
    const deleteQuery = { _id: new ObjectId(commentId) };
    const result = await comment.deleteOne(deleteQuery);

    if (result.deletedCount === 0) {
      console.log('No comment found to delete.');
    } else {
      console.log('Comment deleted.');
    }
  } catch (error) {
    console.error('Error deleting comment:', error);
  }

  res.redirect('/viewUser_Com');
});



server.get('/edit_comments', isAuthenticated, function(req, resp){
  const { text } = req.query;

  resp.render('editComment',{
    layout: 'index3',
    title: 'Edit Comment',
    prevCom: text
  });
  
  console.log(text);
});

server.get('/reply', isAuthenticated, function(req, resp){
  resp.render('reply',{
      layout: 'index3',
      title: 'Reply'
  });
});

server.get('/edit_posts', isAuthenticated, function(req, resp){
  const { title } = req.query;

  resp.render('editPost',{
      layout: 'index4',
      title: 'Edit Post',
      OGTitle: title
  });

  console.log(title);
});

//Only at the very end should the database be closed.
function finalClose(){
  console.log('Close connection at the end!');
  mongoClient.close();
  process.exit();
}

process.on('SIGTERM',finalClose);  //general termination signal
process.on('SIGINT',finalClose);   //catches when ctrl + c is used
process.on('SIGQUIT', finalClose); //catches other termination commands

const port = process.env.PORT | 3000;
server.listen(port, function(){
  console.log('Listening at port '+port);
});