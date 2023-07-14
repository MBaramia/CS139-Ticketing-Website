# README

Main applications:

User Verification and login

Organiser Verification and login

Organiser adding/cancelling events

Attendees purchasing cancelling Tickets

Viewing User Tickets and Barcodes

Notifications for Attendees based on cancellations

Notifications for organisers based on capacity

Attendees can request multiple tickets

Programs used:

SQLite3

Flask

HTML

CSS

SQLAlchemy

The application has many features, it has four database tables, called User, Organiser, Events and Tickets. Users is a table used for the
Attendee class, Organiser table for storing organiser users, Events table for storing information on the event, and lastly tickets which stores information on the tickets, all being initialised with separate __init__ functions. These are all stored in a sqlite3 database, called User, where all values are stored here.

There are methods for adding values into these tables, such as create_user() and create_organiser(). These are both implemented in their respective register functions, such as register_user() and register_organiser(), considering the conditions are correct. For example, if the passwords do not match, or the code for the organiser is incorrect, then error_messages are rendered on the html pages. These are defined in the logs.css file, where the make-up of the error_messages are defined. By adding email verification, only valid and verifiable email addresses can be added to the database tables. Also, a confirmation email is sent to the email used to login (an extra feature), which uses two functions, generate_passcode() and send_email(). generate_passcode() is used to create a 6 letter string of random lower-case letters, and the send_email() function takes 3 parameters, the recipient, the subject of the email and the body of the email, these are all defined in the respective register_user or register_organiser functions. Security is also being taken into account, using werkzeug Security to hash passwords, using functions such as check_password_hash() and generate_password_hash(). There are separate HTML files used for each of these functions.

The login system works in a similar way to the registration process, there are separate flask routes and HTML pages for users and for organisers, there are also methods such as validate_user() and validate_organiser() which are incorporated, these are just used to ensure that the user or organiser actually exists, and that the correct details are being added, else, error_messages are rendered on the login html pages, such as 'Invalid email or password'.

Once an organiser is logged in, they and only they can add events, as the add events functions, says if 'access_token' in session, this access_token is initialised when creating an organiser, which is a 12 character hex value. The organiser can add an event,with name, date, cost, place and capacity parameters. These can be viewed by everyone on the index.html page, even users who are not logged in. This html file renders the information of the events in a list. Also, only the organisers can cancel_events(), using the same if 'access_token' in session again to ensure only organisers can access this section. Once the event is cancelled, the event is removed from the database table, using db.session.delete(). It is also removed from the list of events on the events_list html page. Also, when the event is cancelled, an email is sent to all the Attendees who have ordered tickets for that event, using the same send_email() function described earlier.

Once an Attendee is logged, they and only they can purchase tickets for events, using if 'access_user' in session, this access_user is initialised when creating an attendee, which is made the same way as the Organiser access_token. The user inputs the event ID, and adds the quantity of tickets which they have purchased. This is then added to the ticket database, considering there are no issues with this. If there is issues, such as requesting tickets for an event which doesn't exist, or buying too many tickets, an error_message is rendered on the purchase_ticket.html page. Once the tickets are purchased, the attendee is redirected to their unique dashboard, where there tickets are presented, each with their own unique bar-code. These bar-codes are created using a for loop, meaning Attendees can request multiple tickets, adding tickets to the database and a 30 character hex value, which is used as a bar-code. This ensures each ticket receives its own unique bar-code. The attendee can also cancel individual tickets, by entering the ticket ID, and this is ticket ID is used to query the Tickets database table, and then this individual ticket can be deleted using db.session.delete(). Once the event has reached maximum capacity, or when the event is near to full capacity, then the organiser also gets an email notification, telling them that their event is reaching full capacity.

Disabled users were also taken into account during the make-up of the css file logs.css. In this file, bright colours are used and a simple font system was used constantly throughout the website. Also, the navigation bar at the top is permanently underlined, ensuring that there is clear navigation for disabled users to help them, and that all headers and important information are not colour coded.
