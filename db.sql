drop table Steganography;
drop table Guest;

SELECT 
    'ALTER TABLE [' +  OBJECT_SCHEMA_NAME(parent_object_id) +
    '].[' + OBJECT_NAME(parent_object_id) + 
    '] DROP CONSTRAINT [' + name + ']'
FROM sys.foreign_keys
WHERE referenced_object_id = object_id('Users')

drop table users;

CREATE TABLE Users (
    username NVARCHAR(50) PRIMARY KEY,
    password NVARCHAR(256) NOT NULL,
    first_name NVARCHAR(50) NOT NULL,
    last_name NVARCHAR(50) NOT NULL
);


CREATE TABLE Steganography (
    operation_id INT IDENTITY(1,1) PRIMARY KEY,
    username NVARCHAR(50) FOREIGN KEY REFERENCES Users(username),
    message_file NVARCHAR(MAX) NOT NULL,
    carrier_file NVARCHAR(MAX) NOT NULL,
    starting_bit INT NOT NULL,
    mode NVARCHAR(10) CHECK (mode IN ('fixed', 'variable')),
    length INT,
    hidden_data NVARCHAR(MAX),
    retrieved_data NVARCHAR(MAX),
    carrier_format NVARCHAR(50),
    message_format NVARCHAR(50)
);


CREATE TABLE Guest (
    guest_id INT IDENTITY(1,1) PRIMARY KEY,
    first_name NVARCHAR(50) NOT NULL,
    last_name NVARCHAR(50) NOT NULL
);
