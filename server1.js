const bcrypt = require('bcrypt');
const PDFDocument = require('pdfkit');
const mysql = require('mysql2');
const crypto =require("crypto")
const express = require('express');
const flash = require('connect-flash');
const bodyParser = require('body-parser');
const { Pool, Connection } = require('pg');
const geocoder = require('geocoder');
const session = require('express-session');
const axios = require('axios');
const db= require("./db")
const app = express();
const nodemailer = require("nodemailer");
const { error, Console } = require('console');
const port = 3000;
app.set('view engine', 'ejs');
app.set('views', 'views');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
require('dotenv').config();
const Razorpay = require('razorpay');


// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


const transporter = nodemailer.createTransport({
 
  // Use Gmail service for sending emails
 service: 'gmail',
 auth: {
   user: process.env.SMTP_MAIL, // SMTP email
   pass: process.env.SMTP_PASS  // SMTP password
 }
});
// Set up session middleware
app.use(session({
  secret: 'PixelPioneers',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 week in milliseconds
}));



// Create a connection to the database
const connection = mysql.createConnection({
  host: 'localhost',        // Replace with your host
  user: 'root',    // Replace with your MySQL username
  password: 'saurabh123',// Replace with your MySQL password
  database: 'trekk' // Replace with your database name
});



// Connect to the database
connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err.stack);
    return;
  }
  console.log('Connected to the database as id ' + connection.threadId);
  
  // SQL query to create a table if it doesn't exist
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // Execute the query
  connection.query(createTableQuery, (error, results, fields) => {
    if (error) {
      console.error('Error creating table:', error.stack);
      return;
    }
    console.log('Table "users" is ready or already exists.');
  });

  // Optionally, you can perform more queries here...

  
  
});
app.use(express.static('public'));


app.get('/treking', (req, res) => {
  const query = 'SELECT * FROM Locationss where category ="trekking"';;
  connection.query(query, (err, results) => {
      if (err) {
          console.error('Error fetching data from database:', err);
          res.status(500).send('Server Error');
          return;
      }
      // Render the EJS template and pass the results
      res.render('treking', { locations: results });
  });
});

app.get('/hiking', (req, res) => {
  const query = 'SELECT * FROM Locationss where category ="hiking"';
  connection.query(query, (err, results) => {
      if (err) {
          console.error('Error fetching data from database:', err);
          res.status(500).send('Server Error');
          return;
      }
      // Render the EJS template and pass the results
      res.render('hiking', { locations: results });
  });
});

app.get('/camping', (req, res) => {
  const query = 'SELECT * FROM Locationss where category ="camping"';
  connection.query(query, (err, results) => {
      if (err) {
          console.error('Error fetching data from database:', err);
          res.status(500).send('Server Error');
          return;
      }
      // Render the EJS template and pass the results
      res.render('camping', { locations: results });
  });
});


app.get('/services', (req, res) => {
  const query = 'SELECT tripId, tripName,imageUrl,distanceFromPune,DATE(startDate) AS startDate,DATE(endDate) AS endDate,price  FROM trips t inner join locationss l on l.id = t.Id where startDate > CURDATE() AND isactive = 1 ORDER BY startDate ASC ';
  connection.query(query, (err, results) => {
      if (err) {
          console.error('Error fetching data from database:', err);
          res.status(500).send('Server Error');
          return;
      }
      // Render the EJS template and pass the results
      res.render('services', { locations: results });
  });
});







// Haversine formula to calculate distance between two points
function haversineDistance(lat1, lon1, lat2, lon2) {
  const toRad = angle => (Math.PI / 180) * angle;
  const R = 6371; // Radius of the Earth in kilometers
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // Distance in kilometers
}

// Route to handle form submission and location search
app.post('/searchLocation', async (req, res) => {
  const { address, maxDistance } = req.body;

  try {
    // Step 1: Convert address to latitude and longitude using Google Maps Geocoding API
    const geocodeResponse = await axios.get(
      `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=AIzaSyAzdPDaqmRQyx9Td6T1DNVQraiRuembKCc`
    );

    if (!geocodeResponse.data.results.length) {
      return res.status(404).json({ message: 'Address not found' });
    }

    const { lat, lng } = geocodeResponse.data.results[0].geometry.location;
    console.log(lat);
    console.log(lng);

    // Step 2: Fetch all locations from your database
    connection.query('SELECT * FROM locationss', (err, results) => {
      if (err) throw err;

      console.log(results);
      // Step 3: Compare distances using the Haversine formula
      const nearbyLocations = results.filter(location => {
        const distance = haversineDistance(lat, lng, location.latitude, location.longitude);
        return distance <= maxDistance; // Filter locations within the max distance
      });

      console.log(nearbyLocations);
      // Step 4: Return the filtered locations
      // res.json(nearbyLocations);
      res.render('location_search', { locations: nearbyLocations });
    });
    

   

  } catch (error) {
    console.error('Error fetching location:', error);
    res.status(500).json({ message: 'Server error' });
  }
});







// // PostgreSQL configuration
// const pool = new Pool({
//     user: 'postgres',
//     host: 'localhost',
//     database: 'treak',
//     password: 'Shivam@12345',
//     port: 5432,
// });



app.get("/payment",(req,res)=>{
  const email = req.session.user.username;
  res.render("payment.ejs")
})




//first_page
app.get("/index",async (req,res)=>{
  if (!req.session.user || !req.session.user.username) {  
    return res.redirect("/indexl"); }
  const email = req.session.user.username;

  
  const user = await db.query('SELECT username FROM users WHERE email = ?', [email]);

  console.log("name" , user[0][0].username);
  const name = user[0][0].username;
  
  
  const query = 'SELECT r.rating, comment,u.username,t.tripName FROM reviews r join users u on r.userId = u.id join trips t on t.tripId = r.tripId order by rating desc ';

  connection.query(query, (error, results) => {
      if (error) {
          console.error('Error fetching reviews: ', error);
          return res.status(500).send('Server error');
      }

     
  
  res.render("index.ejs" , { reviews: results,username : name })
})});


//user_signup_page
app.get("/signup",(req,res)=>{
  res.render("signup.ejs")
})

app.get('/new_sign', (req, res) => {
  const username = req.session.email || ''; // Use session or default to an empty string
  res.render('new_sign', { username });
});

//camping_page
app.get("/camping",(req,res)=>{
    res.render("camping.ejs")
  })


//hiking_page
app.get("/hiking",(req,res)=>{
    res.render("hiking.ejs")
  })

  
//mountaintrek_page
app.get("/mountaintrek",(req,res)=>{
    res.render("mountaintrek.ejs")
  })

  app.get('/mytrips', async (req, res) => {
    const email = req.session.user.username;
    try {
      const pastTripss = await db.query('SELECT l.*, t.*,  b.*,  u.*   FROM locationss l JOIN trips t ON l.id = t.Id JOIN bookinggss b ON t.tripId = b.tripId JOIN users u ON b.user_id = u.id WHERE startDate < CURDATE() and u.email = ?',[email]);
      console.log("Past Trips:", pastTripss[0]);
  
      const upcomingTripss = await db.query('SELECT l.*, t.*,  b.*,  u.*   FROM locationss l JOIN trips t ON l.id = t.Id JOIN bookinggss b ON t.tripId = b.tripId JOIN users u ON b.user_id = u.id WHERE startDate > CURDATE() and u.email = ?',[email]);
      console.log("Upcoming Trips:", upcomingTripss[0]);
  
      const wishlists = await db.query('SELECT * FROM trips WHERE startDate > CURDATE()');  // assuming there's a wishlist table or list linked to user
      console.log("Wishlist:", wishlists[0]);

      const pastTrips = pastTripss[0];
      const upcomingTrips = upcomingTripss[0];
      const wishlist = wishlists[0];

  
      res.render('mytrips', { pastTrips, upcomingTrips, wishlist });
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }  
  });


  app.post('/submitReview', async (req, res) => {
    const { tripId, review, rating } = req.body; // Extract tripId, reviewText, and rating from request body
    const email = req.session.user.username; // Get the user's email from the session
  
    try {
      // Retrieve the user ID based on the email in session
      const userResult = await db.query('SELECT id FROM users WHERE email = ?', [email]);
      const userId = userResult[0][0].id;
  
      if (!userId) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
  
      // Insert the review into the "reviews" table
      await db.query('INSERT INTO reviews (tripId, userId, comment, rating) VALUES (?, ?, ?, ?)', [tripId, userId, review, rating]);
  
      // Send JSON success response
      res.status(200).json({ success: true, message: 'Review submitted successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
  });
  




//register_page
app.get("/register",(req,res)=>{
    res.render("register.ejs")
  })



//signout
app.get("/indexl",(req,res)=>{
  res.render("indexl.ejs")
})


// //newsignpage
// app.get("/new_sign",(req,res)=>{
//   res.render("new_sign.ejs")
// })



//treking_page
app.get("/treking",(req,res)=>{
    res.render("treking.ejs")
  })

  app.get("/search",(req,res)=>{
    res.render("search.ejs")
  })
  app.get("/edit-profile", async(req,res) => {
      const email = req.session.user.username;
      // const name = req.query.name;
      console.log("email : " + email);
      
    
      try {
          const owner = await db.query('SELECT * FROM users WHERE email = ?', [email]);
          console.log("owner:", owner[0]);
          
    
          const user1 = owner[0][0];
    
    
          console.log(user1);
  
          console.log('user email:',user1.email);
          res.render("edit-profile.ejs", { user1 })
        } catch (err) {
          console.error(err);
          res.status(500).send('Internal Server Error');
    
   
      }
  })

  app.get('/profile', async (req, res) => {
    const email = req.session.user.username;
    // const name = req.query.name;
    console.log("email : " + email);
    
  
    try {
        const owner = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        console.log("owner:", owner[0]);
        
  
        const user1 = owner[0][0];
  
  
        console.log(user1);

        console.log('user email:',user1.email);
  
        res.render('profile', { user1 });
  
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
  });

  // Update profile route
app.post('/update-profile', (req, res) => {

  const email = req.session.user.username;

    const { username, gender, mobile_number, address, dob, blood_group } = req.body;
     // Assuming you have user ID stored in session

     console.log("username, gender, mobile_number, address, dob, blood_group" ,email, username , gender, mobile_number, address, dob, blood_group)

    const query = `
        UPDATE users 
        SET gender = ?, mobile_number = ?, address = ?, dob = ?, blood_group = ?
        WHERE email = ?
    `;



    connection.query(query, [ gender, mobile_number, address, dob, blood_group, email], (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).send('Error updating profile');
            return;
        }
        res.redirect('/profile');
    });
});

// Serve the edit profile page
app.get('/edit-profile', (req, res) => {
    const userId = req.session.userId; // Assuming you have user ID stored in session
    const query = `SELECT * FROM users WHERE id = ?`;

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error(err);
            res.status(500).send('Error retrieving profile');
            return;
        }

        res.render('edit-profile', { user1: results[0] }); // Assuming you are using a template engine like EJS
    });
});



// Signup endpoint
app.post('/signup', async (req, res) => {
    console.log("aaaa")
    
      
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
  /*
    const email=req.session.mail
    const password=req.session.password
  
    const name="Shivam"*/
  
    connection.connect(async (err) => {
      if (err) {
        console.error('Error connecting to the database:', err.stack);
        res.status(500).json({ success: false, message: 'Database connection failed' });
        return;
      }
  
      // Check if user with the given email already exists
      connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
          console.error('Error executing query', err);
          res.status(500).json({ success: false, message: 'An error occurred during the query execution' });
          
          return;
        }
  
        if (results && results.length > 0) {
          res.status(409).json({ success: false, message: 'User with this email already exists' });
          
        } else {
          try {
            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds
  
            // Insert new user record with hashed password
            connection.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (err, insertResults) => {
              if (err) {
                console.error('Error inserting user', err);
                res.status(500).json({ success: false, message: 'An error occurred during the user insertion' });
              } else {
                // Destroy the session and render login page
                req.session.destroy((sessionErr) => {
                  if (sessionErr) {
                    console.error('Error destroying session', sessionErr);
                    res.status(500).json({ success: false, message: 'An error occurred while destroying the session' });
                  } else {
                    res.render("new_sign");
                  }
                });
              }
             
            });
          } catch (hashErr) {
            console.error('Error hashing password', hashErr);
            res.status(500).json({ success: false, message: 'An error occurred while hashing the password' });
            
          }
        }
      });
    
        });
      });
  


//forgot pass 
app.get("/forgetpassword",(req,res)=>{
  
  res.render("forgotpass",{errorMessage:""})
})


app.post("/forget-password", async (req, res) => {
  const username = req.body.email;
  const sql = "SELECT * FROM users WHERE email=?";

  try {
    const [result] = await db.query(sql, [username]);
    
    // Debugging the query result
    console.log('Query result:', result);

    if (result.length > 0) {
      const user = result[0];
      console.log('User from DB:', user);

      // Generate OTP
      const otp = crypto.randomInt(100000, 999999).toString();
      console.log('Generated OTP:', otp);

      // Store OTP in OTP_MASTER table
      await db.query(
        'INSERT INTO OTP_MASTER ( EMAIL_ID, OTP, STATUS) VALUES ( ?, ?, "active")',
        [username, otp]
      );

      // Send OTP to user's email
      let mailOptions = {
        from: process.env.EMAIL_USERNAME, // Check if EMAIL_USERNAME is properly set
        to: username,
        subject: 'Password Reset',
        text: `
         Dear ${username},
         We received a request to reset the password for your TreKathon account. Please use the One-Time Password (OTP) below to reset your password:

        OTP: ${otp}

        If you did not request a password reset, please ignore this email or contact our support team if you have any concerns.

        For your security, this OTP will expire in 15 minutes.

        Thank you for using TreKathon!

        Best regards,
        The TreKathon Team ` // Backticks for interpolation
      };

      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log('Error while sending email:', error);
        } else {
          console.log('Email sent:', info.response);
        }
      });

      // Render verification page
      res.render("./verify", { username: username });
    } else {
      console.log('User not found with the provided email:', username);
      res.render("./forgotpass", { errorMessage: "User not found" });
    }
  } catch (error) {
    console.error('Error during password reset process:', error);
    res.render("./forgotpass", { errorMessage: error.message });
  }
});

app.post('/verify', async function (req, res) {
  const username = req.body.username;
  const otp = req.body.otp;
  console.log('Username:', username);
  console.log('OTP:', otp);

  try {
      // Fetch the most recent OTP with 'active' status for the user
      const [q] = await db.query(
          `SELECT otp, CREATED_AT FROM otp_master 
          WHERE email_id = ? AND status = 'active' 
          ORDER BY CREATED_AT DESC LIMIT 1;`,
          [username]
      );

      if (q.length === 0) {
          console.log('No active OTP found.');
          return res.render('./new_sign', {message:"",username:"", error: 'No active OTP found. Please request a new OTP.' });
      }

      const otpData = q[0]; // Access the first row
      const oldOTP = otpData.otp;
      const timestamp = new Date(otpData.CREATED_AT).getTime(); // Convert to milliseconds
      console.log('Old OTP:', oldOTP, 'Timestamp:', timestamp);

      const currentTime = new Date().getTime();

      // Check if the OTP has expired (older than 5 minutes)
      if (currentTime - timestamp > 300000) { // 300000 ms = 5 minutes
          console.log('The OTP has expired. Please request a new OTP.');
          return res.render('./new_sign', {message:"",username:"", error: 'The OTP has expired. Please request a new OTP.' });
      }

      // Validate OTP
      if (String(oldOTP) !== String(otp)) {
          console.log('Invalid OTP.');
          return res.render('./verify', { error: 'Invalid OTP.', username });
      } else {
          console.log('OTP verified successfully.');

          // Mark the OTP as inactive after successful verification
          await db.query(
              'UPDATE otp_master SET status = "inactive" WHERE email_id = ? AND otp = ?',
              [username, otp]
          );

          // Redirect to reset-password page
          res.redirect(`/reset-password?user_id=${encodeURIComponent(username)}`);
      }
  } catch (err) {
      console.log('Error during OTP verification:', err);
      res.render('./new_sign', { error: 'An error occurred during OTP verification. Please try again.' });
  }
});
app.get("/reset-password",(req,res)=>{
  const user_id=req.query.user_id
  res.render("./reset-password",{user_id})

})
app.post("/reset-password",async(req,res)=>{
const {email,newPassword,confirmPassword}=req.body
console.log(email,newPassword,confirmPassword)
const hashedPassword = await bcrypt.hash(newPassword, 10); // 10 is the salt rounds
await db.query(
  'UPDATE users SET password = ? WHERE email = ? ',
  [hashedPassword,email]
  
);
res.render("./new_sign",{username:email,message:"Password Changed !!!!",error:""})

});













// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  connection.connect((err) => {
    if (err) {
      console.error('Error connecting to the database:', err.stack);
      res.status(500).json({ success: false, message: 'Database connection failed' });
      return;
    }

    // Fetch user record by email
    connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Error executing login query', err);
        res.status(500).json({ success: false, message: 'An error occurred during the login process' });
        
        return;
      }
      console.log(results)

      if (results.length > 0) {
        const user = results[0];

        // Compare the entered password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);
        console.log(password)
        console.log(user.password)

        if (isMatch) {
          // Passwords match, login successful
          req.session.user = { username: email };
          console.log(req.session.user);
          res.redirect('/index');
        } else {
          // Passwords do not match
          res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
      } else {
        // No user found with the given email
        res.status(401).json({ success: false, message: 'Invalid credentials' });
      }
    
    });
  });
});








  app.get('/signout', (req, res) => {
    // Destroy the session
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            // Handle error, if any
        } else {
            // Redirect the user to the home page
            res.redirect('/indexl');
        }
    });
  });
//admin portal


//admin_login
app.get("/adminlogin",(req,res)=>{
  res.render("adminlogin.ejs")
})


app.get("/add-adventure",(req,res)=>{
  res.render("add-adventure.ejs")
})
app.get("/mission",(req,res)=>{
  res.render("mission.ejs")
})

app.get("/story",(req,res)=>{
  res.render("story.ejs")
})

app.get("/team",(req,res)=>{
  res.render("team.ejs")
})

app.get("/contact",(req,res)=>{
  res.render("contact.ejs")
})


// app.get("/adminmanage-bookings",(req,res)=>{
//   res.render("adminmanage-bookings.ejs")
// })




// Login endpoint
app.post('/adminlogin', (req, res) => {
  const { email, password } = req.body;

  // Hardcoded admin credentials check
  if (email === 'admin@gmail.com' && password === 'admin1234') {
    // Successful login for hardcoded credentials
    req.session.user = { username: email };
    console.log(req.session.user);
    return res.redirect('/admin_dash');
  }
  else {
    // Passwords do not match
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});
//locationss
// Routes
app.get('/add-adventure', (req, res) => {
  res.render('add-adventure');
});

// Route to handle form submission
app.post('/submit-location', (req, res) => {
  try {
    const { locationName, place, latitude, longitude, distanceFromPune, attractions, imageUrl, descriptions } = req.body;
    console.log("Received data:", req.body);  // Log received data

    const sql = 'INSERT INTO locationss (locationName, place, latitude, longitude, distanceFromPune, attractions, imageUrl, descriptions) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    const values = [locationName, place, latitude, longitude, distanceFromPune, attractions, imageUrl, descriptions];

    connection.query(sql, values, (err, result) => {
      if (err) {
        console.error('Database insertion error:', err);  // Log the error
        return res.status(500).send('Internal Server Error');
      } else {
        console.log("Database insertion successful:", result);  // Log successful insertion
        res.redirect('/admin_dash');
      }
    });
  } catch (error) {
    console.error('Unexpected error:', error);  // Log unexpected errors
    res.status(500).send('Internal Server Error');
  }
});


  app.listen(port, () => {
    console.log(`Server is running on port ${port}`); 
  });

// Route to render the adminsettings page
app.get('/adminsettings', async (req, res) => {
  const sql = 'SELECT id, locationName FROM locationss';

  try {
    // Execute the SQL query
    const [results] = await db.query(sql);
    console.log('Query Results:', results);

    // Ensure results are correctly passed to the template
    if (results.length === 0) {
      console.warn('No locations found in the database.');
    }
    
    // Pass the results (locations) to the template
    res.render('adminsettings', { results });
  } catch (err) {
    console.error('Database query error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Route to handle form submission
app.post('/submit-trip', (req, res) => {
  const { tripName, locationId, startDate, endDate, coordinatorId, new_coordinator_name, new_coordinator_contact, tripDescription, vacancy, price } = req.body;

  // Insert the new trip into the trips table
  const sql = 'INSERT INTO trips (tripName, id, startDate, endDate, coordinatorId, tripDescription, vaccancy, price) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  const values = [tripName, locationId, startDate, endDate, coordinatorId, tripDescription, vacancy, price];

  connection.query(sql, values, (err, result) => {
    if (err) {
      console.error('Database insertion error:', err);
      return res.status(500).send('Internal Server Error');
    }

    // Redirect to the admin dashboard after successful insertion
    res.redirect('/admin_dash');
  });
});
 
// Route to fetch and display users
app.get('/adminmanage_user', async (req, res) => {

  const query = 'SELECT * FROM users';
  connection.query(query, (err, results) => {
      if (err) {
          console.error('Error fetching data from database:', err);
          res.status(500).send('Server Error');
          return;
      }

      console.log(results);
      // Render the EJS template and pass the results
      res.render('adminmanage_user', { users: results });
  });


});
// app.get('/book', async (req, res) => {
//   const locationId = req.params.locationId; // Retrieve locationId from URL parameters
//   const query = `
//       SELECT trips.*, locationss.*
//       FROM trips
//       JOIN locationss ON trips.Id = locationss.id
//       WHERE locationss.id = ?
//   `;

//   connection.query(query, [locationId], (err, result) => {
//       if (err) {
//           console.error('Error executing query:', err);
//           return res.status(500).send('Internal Server Error');
//       }
//       if (result.length > 0) {
//           // Render the EJS template and pass the result
//           console.log(results);
//           return res.render('/book', { location: result[0] });
//       } else {
//           return res.send('Location not found');
//       }
//   });
// });
app.get('/book', (req, res) => {
  const tripId = req.query.buttonData; // Get tripId from URL parameters
  console.log('trip_id', tripId); // Log the tripId
  req.session.tripid = { trip_id: tripId };
  console.log(req.session.tripid);

  const query = `
      SELECT trips.*, locationss.*
      FROM trips
      JOIN locationss ON trips.Id = locationss.id
      WHERE trips.tripId = ? AND startDate > CURDATE()
  `;

  connection.query(query, [tripId], (err, results) => {
      if (err) {
          console.error('Error fetching data from database:', err);
          res.status(500).send('Server Error');
          return;
      }
      console.log('Query Results:', results); // Log results

      const query1 = `SELECT Vaccancy
      FROM trips where tripId = ?`;

      connection.query(query1, [tripId], (err, results1) => {
        if (err) {
            console.error('Error fetching data from database:', err);
            res.status(500).send('Server Error');
            return;
        }
        console.log('Query Results:', results1[0]); // Log results


      if (results.length > 0) {
          res.render('book', { trip: results[0],vacany: results1[0] });
      } else {
          res.send('No trip found or the trip has already started.');
      }
  });
});
});



app.post('/booking_form', (req, res) => {
  const emaill = req.session.user.username;
  const tripid = req.session.tripid.trip_id;
  console.log("emal",emaill);
  console.log("trp",tripid);
  const query = 'SELECT id FROM users where email = ?';
  connection.query(query, [emaill], (err, id_) => {
      if (err) {
          console.error('Error fetching data from database:', err);
          res.status(500).send('Server Error');
          return;
      }

      const { email, mobile, people, participants,totalAmount } = req.body;
      console.log(participants);
      console.log(id_[0].id);
      console.log("totalAmount",totalAmount);

      req.session.userid = { userid: id_[0].id };
      console.log(req.session.userid.userid);


      req.session.amt = { amount: totalAmount };
      console.log(req.session.amt.amount);


      // Insert into bookings
      const bookingQuery = 'INSERT INTO bookinggss (email, mobile, number_of_people, user_id,tripId) VALUES (?, ?, ?, ?,?)';
      connection.query(bookingQuery, [email, mobile, people, id_[0].id,tripid], (err, result) => {
          if (err) throw err;
          const bookingId = 1; // Get the booking_id

          const query1 = 'SELECT booking_id FROM bookinggss where email = ? and tripId = ? and user_id =?';
          connection.query(query1, [email,tripid,id_[0].id], (err, bookid) => {
            if (err) {
                console.error('Error fetching data from database:', err);
                res.status(500).send('Server Error');
                return;
            }
            console.log(bookid[0].booking_id);
            req.session.bookinid = { bookid: bookid[0].booking_id };
            console.log(req.session.bookinid.bookid);

         // Insert each participant
const participantQuery = 'INSERT INTO participantss (booking_id, name, gender, age) VALUES (?, ?, ?, ?)';
participants.forEach(participant => {
    connection.query(participantQuery, [bookid[0].booking_id, participant.name, participant.gender, participant.age], (err) => {
        if (err) throw err;
    });
});

// Update the trips table to reduce the vacancy by the number of people
const updateVacancyQuery = 'UPDATE trips SET Vaccancy = Vaccancy - ? WHERE tripId = ?';
connection.query(updateVacancyQuery, [people, tripid], (err, result) => {
    if (err) {
        console.error('Error updating vacancy in the trips table:', err);
        res.status(500).send('Server Error');
        return;
    }


          res.redirect('payment');
      });
  });
});
});
});


// Route to fetch trips and render the bookings page
app.get('/adminmanage-bookings', (req, res) => {
  // Query to fetch available trips
  const tripsQuery = `SELECT tripId, tripName FROM trips where startDate > CURDATE()`;

  connection.query(tripsQuery, (err, trips) => {
    if (err) {
      console.error('Error fetching trips:', err);
      return res.status(500).send('Server Error');
    }

    // Render the page with the fetched trips
    res.render('adminmanage-bookings', { bookings: trips });
  });
});

// Route to fetch bookings for a specific trip
app.get('/getBookingsByTrip', (req, res) => {
  const tripId = req.query.tripId;

  if (!tripId) {
    return res.status(400).json({ error: 'Trip ID is required' });
  }

  // Query to fetch bookings and participants for the selected trip
  const bookingsQuery = `
    SELECT b.booking_id, b.email, b.mobile, b.number_of_people, b.booking_date AS date,
           p.name AS participant_name, p.age,p.gender
    FROM bookinggss b
    LEFT JOIN participantss p ON b.booking_id = p.booking_id
    WHERE b.tripId = ?;
  `;

  connection.query(bookingsQuery, [tripId], (err, results) => {
    if (err) {
      console.error('Error fetching bookings:', err);
      return res.status(500).json({ error: 'Server Error' });
    }

    // Format the results to group participants by booking
    const bookings = {};
    results.forEach(row => {
      if (!bookings[row.booking_id]) {
        bookings[row.booking_id] = {
          booking_id: row.booking_id,
          email: row.email,
          mobile: row.mobile,
          number_of_people: row.number_of_people,
          date: row.date,
          participants: []
        };
      }

      // Add participants to the booking if available
      if (row.participant_name) {
        bookings[row.booking_id].participants.push({
          name: row.participant_name,
          age: row.age
        });
      }
    });

    // Send the bookings data in JSON format
    res.json({ bookings: Object.values(bookings) });
  });
});


const razorpay = new Razorpay({
  key_id: 'rzp_test_Hdn2zY77HAdaJq',
  key_secret: 'K4KvhQUd7B7IUpflMv7yFtwt',
});
// Create the order endpoint
app.post('/create-order', async (req, res) => {
  const amount = req.session.amt.amount * 100; // Amount in paise

  const options = {
      amount: amount, // amount in paise
      currency: 'INR',
  };

  try {
      const order = await razorpay.orders.create(options);
      res.json(order);
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Something went wrong!' });
  }
});

// Endpoint to verify the payment
app.post('/verify-payment', (req, res) => {
  const { order_id, payment_id, signature, amount } = req.body;
  console.log(req.body);

  // Generate the expected signature
  const generatedSignature = crypto.createHmac('sha256', 'K4KvhQUd7B7IUpflMv7yFtwt')
      .update(order_id + '|' + payment_id)
      .digest('hex');

  // Verify the signature
  if (generatedSignature === signature) {
    // Payment is successful, save details in the database
    const paymentDetails = {
        bookingId : req.session.bookinid.bookid,
        userId : req.session.userid.userid,
        order_id: order_id,
        payment_id: payment_id,
        status: 'success',
        amount: amount, // Ensure this value is available or pass from frontend
        created_at: new Date()
      };

      db.query('INSERT INTO payments SET ?', paymentDetails, (err, result) => {
          if (err) {
              return res.status(500).json({ success: false, error: 'Database error' });
          }
          res.json({ success: true, message: 'Payment verified and details stored.' });
      });
  } else {
      // Signature does not match
      res.status(400).json({ success: false, message: 'Payment verification failed!' });
  }
});




app.get('/admin_dash', async (req, res) => {
  try {
      const totalUsers = await db.query('SELECT COUNT(*) AS count FROM users');
      const maleUsers = await db.query('SELECT COUNT(*) AS count FROM users WHERE gender = "Male"');
      const femaleUsers = await db.query('SELECT COUNT(*) AS count FROM users WHERE gender = "Female"');

      const totalBookings = await db.query('SELECT COUNT(*) AS count FROM bookinggss');
      const maleBookings = await db.query('SELECT COUNT(*) AS count FROM bookinggss WHERE booking_id IN (SELECT id FROM users WHERE gender = "Male")');
      const femaleBookings = await db.query('SELECT COUNT(*) AS count FROM bookinggss WHERE booking_id IN (SELECT id FROM users WHERE gender = "Female")');

      const totalTrips = await db.query('SELECT COUNT(*) AS count FROM trips');
      const completedTrips = await db.query('SELECT COUNT(*) AS count FROM trips WHERE startDate < NOW()'); // Completed trips
      const upcomingTrips = await db.query('SELECT COUNT(*) AS count FROM trips WHERE startDate > NOW()'); // Upcoming trips

      // Combine the statistics into an object
      const stats = {
          totalUsers: totalUsers[0][0].count,
          maleUsers: maleUsers[0][0].count,
          femaleUsers: femaleUsers[0][0].count,
          totalBookings: totalBookings[0][0].count,
          maleBookings: maleBookings[0][0].count,
          femaleBookings: femaleBookings[0][0].count,
          totalTrips: totalTrips[0][0].count,
          completedTrips: completedTrips[0][0].count,
          upcomingTrips: upcomingTrips[0][0].count
      };

      // Log the statistics for debugging
      console.log('Statistics:', stats);

      res.render('admin_dash', { stats });
  } catch (error) {
      console.error('Error fetching statistics:', error);
      res.status(500).send('Internal Server Error');
  }
});

// // Route to fetch location details
// app.get('/locations/:id', (req, res) => {
//   const locationId = req.params.id;
  
//   const query = 'SELECT * FROM locationss WHERE id = ?'; // Ensure you are using prepared statements to avoid SQL Injection
//   connection.query(query, [locationId], (error, results) => {
//       if (error) {
//           return res.status(500).send('Server error');
//       }

//       if (results.length > 0) {
//           const location = results[0];
//           res.render('location_details', { location }); // Render the location detail page with fetched data
//       } else {
//           res.status(404).send('Location not found');
//       }
//   });
// });

app.get('/location_details', (req, res) => {
  const locationId = req.query.buttonData;
  console.log(locationId);
  
  const query = 'SELECT * FROM locationss WHERE id = ?'; // Ensure you are using prepared statements to avoid SQL Injection
  connection.query(query, [locationId], (error, results) => {
      if (error) {
          return res.status(500).send('Server error');
      }

      if (results.length > 0) {
          const location = results[0];
          res.render('location_details', { location }); // Render the location detail page with fetched data
      } else {
          res.status(404).send('Location not found');
      }
  });
});


// Route to display trips (using async/await)
app.get('/adminmanage_trips', async (req, res) => {
  try {
      const [trips] = await db.query('SELECT * FROM trips');
      res.render('adminmanage_trips', { trips });
  } catch (err) {
      console.error('Error fetching trips:', err);
      res.status(500).send('Server error');
  }
});

// Route to handle activating/deactivating a trip
app.post('/trips/update', async (req, res) => {
  const { tripId, active } = req.body;
  try {
      // Update the isactive field instead of active
      await db.query('UPDATE trips SET isactive = ? WHERE tripId = ?', [active === 'true', tripId]);
      res.redirect('/adminmanage_trips');
  } catch (err) {
      console.error('Error updating trip status:', err);
      res.status(500).send('Server error');
  }
});

// // Route to fetch reviews
// app.get('/reviews', (req, res) => {
//   const query = 'SELECT rating, comment FROM reviews';

//   db.query(query, (error, results) => {
//       if (error) {
//           console.error('Error fetching reviews: ', error);
//           return res.status(500).send('Server error');
//       }

//       res.render('reviews', { reviews: results });
//   });
// });


// app.get('/details', (req, res) => {
//   const tripId = req.query.buttonData; // Get tripId from URL parameters
//   console.log('trip_id', tripId); // Log the tripId
//   req.session.tripid = { trip_id: tripId };
//   console.log(req.session.tripid);

//   const query = `
//       SELECT trips.*, locationss.*
//       FROM trips
//       JOIN locationss ON trips.Id = locationss.id
//       WHERE trips.tripId = ? AND startDate > CURDATE()
//   `;

//   connection.query(query, [tripId], (err, results) => {
//       if (err) {
//           console.error('Error fetching data from database:', err);
//           res.status(500).send('Server Error');
//           return;
//       }
//       console.log('Query Results:', results); // Log results

//       const query1 = `SELECT Vaccancy
//       FROM trips where tripId = ?`;

//       connection.query(query1, [tripId], (err, results1) => {
//         if (err) {
//             console.error('Error fetching data from database:', err);
//             res.status(500).send('Server Error');
//             return;
//         }
//         console.log('Query Results:', results1); // Log results


//       if (results.length > 0) {
//           res.render('book', { trip: results[0],vacany: results1[0] });
//       } else {
//           res.send('No trip found or the trip has already started.');
//       }
//   });
// });
// });
