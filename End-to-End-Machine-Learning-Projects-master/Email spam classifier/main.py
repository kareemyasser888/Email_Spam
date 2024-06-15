from flask import Flask, render_template, request, redirect, url_for, flash
import pickle

import sqlite3

app = Flask(__name__)


app.secret_key = 'ada5sd45saf45sa4f5s4ad5as'  # Set the secret key

# Function to create SQLite database and table
def create_table():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
        '''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, password TEXT)'''
    )
    conn.commit()
    conn.close()

create_table()

pipe = pickle.load(open("Naive_model.pkl","rb"))

@app.route('/', methods=["GET","POST"])
def main_function():
    if request.method == "POST":
        text = request.form
        # print(text)
        emails = text['email']
        print(emails)
        
        list_email = [emails]
        # print(list_email)
        output = pipe.predict(list_email)[0]
        print(output)


        return render_template("show.html", prediction = output)
    
    else:
        return render_template("index.html")


import bcrypt

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Connect to the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        try:
            # Insert user data into the database
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
        except Exception as e:
            flash(f"{e}")
            return redirect(url_for('signup'))  # Redirect back to signup page on error
        
        # Commit changes and close the connection
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))  # Redirect to login page after signup
        
    else:
        return render_template("signup.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Connect to the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Retrieve hashed password from the database
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        result = c.fetchone()
        
        if result:
            hashed_password = result[0]
            # Check if the entered password matches the hashed password
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                # Passwords match, user is authenticated
                flash("Login successful")
                # Redirect to home
                return redirect('/')
            else:
                flash("Invalid username or password")
                return render_template("login.html")
        else:
            flash("Invalid username or password")
            return render_template("login.html")
    else:
        return render_template("login.html")


if __name__ == '__main__':
    app.run(debug=True)