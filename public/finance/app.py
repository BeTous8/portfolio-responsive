import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # stocks
    # number of shares
    # current price of each stock
    # total value of each holding (shares*price)
    # current cash balance and the grant total

    id = session["user_id"]
    print(id)
    rows = db.execute("SELECT name, stock, SUM(shares) as Shares, price, SUM(shares)*price as total, budget as Cash_Balance from transactions where user_id = ? GROUP BY stock, Shares order by Cash_Balance desc", id)
    print(rows)
    return render_template("index.html", portfolio = rows)

    # return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":


        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Stock field is left blank!")
        stock = lookup(symbol)
        if not stock:
            return apology("The stock symbol is not correct.")

        stock_symbol = stock["symbol"]
        stock_price = stock["price"]
        shares = request.form.get("shares")
        if not shares:
            return apology("Shares field is left blank!")
        # print(type(shares))
        # print(type(stock_price))
        total = float(shares) * stock_price
        reset_price = "10000"

        print(stock)

        user_id = session["user_id"]
        user_table = db.execute("SELECT * from users where id = ?", user_id )
        name = user_table[0]["username"]
        # print(type(available_cash[0]["cash"]))
        budget = user_table[0]["cash"] - total
        if budget < total:
            return apology("Sorry - There is not enough cash to complete the transaction")
        else:
            db.execute("INSERT INTO transactions (user_id, name, stock, shares, price, total, budget) VALUES (?, ?, ?, ?, ?, ?, ?)", user_id, name, stock_symbol , shares, stock_price, total, budget)
            db.execute("UPDATE users SET cash = ? where id = ?", budget, user_id)
            # db.execute("UPDATE users SET cash = ? WHERE id = ?", reset_price, user_id)
            return redirect("/")
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("quote")
        stock_info = lookup(symbol)
        return render_template("quoted.html", name=stock_info)
    else:
        return render_template("quote.html")
    # return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        name = request.form.get("username")
        password = request.form.get("password")
        hash = generate_password_hash(password, method='pbkdf2', salt_length=16)
        confirmation = request.form.get("confirmation")
        rows = db.execute("SELECT * from users where username = ?", name)
        print(f"the rows is: {rows}")
        if not rows and name and password and password == confirmation:
            print("the user is not in the database")
            db.execute("INSERT INTO users (username, hash)  VALUES(?, ?)", name, hash)

        elif rows:
            return apology("Sorry - the username already exists!", 300)
        elif not name or not password or password != confirmation:
            return apology("Sorry - the username/password is left blank or the passwords do not match!")

    return render_template("register.html")
    # return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


if __name__ == '__main__':
    app.run(debug=True)