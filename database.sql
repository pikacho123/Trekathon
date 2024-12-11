

CREATE TABLE users (
    id INT NOT NULL PRIMARY KEY,
    username VARCHAR(225),
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    gender VARCHAR(10),
    mobile_number VARCHAR(15),
    address VARCHAR(255),
    dob DATE,
    blood_group VARCHAR(3),
    Emergency_contact VARCHAR(15)
);

CREATE TABLE locationss (
    id INT NOT NULL PRIMARY KEY,
    locationName VARCHAR(100) NOT NULL,
    place VARCHAR(100),
    latitude DECIMAL(8,5),
    longitude DECIMAL(8,5),
    distanceFromPune DECIMAL(5,2),
    attractions TEXT,
    imageUrl VARCHAR(255),
    Descriptions TEXT,
    category ENUM('trekking', 'hiking', 'camping') NOT NULL
);

CREATE TABLE bookings (
    booking_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    mobile VARCHAR(15) NOT NULL,
    number_of_people INT NOT NULL,
    booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INT,
    tripId INT,
    CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_tripId FOREIGN KEY (tripId) REFERENCES trips(tripId)
);

CREATE TABLE otps (
    OTP_ID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    EMAIL_ID VARCHAR(255) NOT NULL,
    OTP VARCHAR(6) NOT NULL,
    STATUS VARCHAR(50) DEFAULT 'active',
    CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE participantss (
    participant_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    booking_id INT,
    name VARCHAR(255) NOT NULL,
    age INT NOT NULL,
    gender ENUM('Male', 'Female', 'Other') NOT NULL DEFAULT 'Other',
    CONSTRAINT fk_booking_id FOREIGN KEY (booking_id) REFERENCES bookings(booking_id)
);
CREATE TABLE payments (
    paymentId INT NOT NULL PRIMARY KEY,
    bookingId INT,
    userId INT,
    amount DECIMAL(10,2) NOT NULL,
    paymentDate DATE NOT NULL,
    paymentMethod VARCHAR(50),
    paymentStatus VARCHAR(50),
    transactionId VARCHAR(100) UNIQUE,
    CONSTRAINT fk_bookingId FOREIGN KEY (bookingId) REFERENCES bookings(booking_id),
    CONSTRAINT fk_userId FOREIGN KEY (userId) REFERENCES users(user_id)
);
CREATE TABLE reviews (
    reviewId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    userId INT,
    tripId INT,
    rating INT,
    comment TEXT,
    reviewDate DATE,
    CONSTRAINT fk_userId FOREIGN KEY (userId) REFERENCES users(user_id),
    CONSTRAINT fk_tripId FOREIGN KEY (tripId) REFERENCES trips(tripId)
);
CREATE TABLE trips (
    tripId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    tripName VARCHAR(100) NOT NULL,
    Id INT,
    startDate DATE NOT NULL,
    endDate DATE NOT NULL,
    coordinatorId INT,
    tripDescription TEXT,
    Vaccancy INT,
    price DECIMAL(10,2) NOT NULL,
    isactive TINYINT(1) DEFAULT 1,
    CONSTRAINT fk_Id FOREIGN KEY (Id) REFERENCES locations(id),
    CONSTRAINT fk_coordinatorId FOREIGN KEY (coordinatorId) REFERENCES users(user_id)
);
