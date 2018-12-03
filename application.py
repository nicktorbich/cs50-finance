import os
import psycopg2

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def after_request(response):
    """ Ensure responses aren't cached """

    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL(os.environ.get("DATABASE_URL") or "sqlite:///finance.db")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get the stocks the user owns
    stocks = db.execute("SELECT symbol, SUM(shares) FROM transactions WHERE userid=:user_id GROUP BY symbol",
                        user_id=session["user_id"])

    stock = []

    for i in range(len(stocks)):
        if stocks[i]['SUM(shares)'] != 0:
            stock.append(stocks[i])

    stocks = stock

    # Get the current price of each
    for i in range(len(stocks)):
        current_values = lookup(stocks[i]['symbol'])
        stocks[i]['name'] = current_values['name']
        stocks[i]['price'] = current_values['price']

    # Total value of each holding
    for i in range(len(stocks)):
        stocks[i]['total'] = stocks[i]['price'] * stocks[i]['SUM(shares)']

    # Get current cash balance
    current_cash = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session["user_id"])

    # Calculate the grand total
    grand_total = 0
    for i in range(len(stocks)):
        grand_total += stocks[i]['total']
    grand_total += current_cash[0]['cash']

    # Convert price and total into dollars
    for i in range(len(stocks)):
        stocks[i]['total'] = usd(stocks[i]['total'])
        stocks[i]['price'] = usd(stocks[i]['price'])

    # Header names
    header = ['Symbol', 'Name', 'Shares', 'Price', 'TOTAL']

    return render_template("index.html", stocks=stocks, cash=usd(current_cash[0]['cash']), total=usd(grand_total), header=header)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")
    elif request.method == "POST":
        # Get data from the form
        symbol = request.form.get("symbol")

        # If there is no symbol or field is blank
        if not symbol or not lookup(symbol):
            return apology("no symbol found")

        # If number of shares is not a positive integer
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("not a positive number")

        if shares < 1:
            return apology("need more shares")

        # Get current data
        current_stock = lookup(symbol)
        current_price = current_stock["price"]
        current_cash = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session["user_id"])

        # Check if the user has enough cash to buy that many stocks
        if current_cash[0]['cash'] < current_price * shares:
            return apology("not enough cash")
        else:
            # Update the transaction table
            db.execute("INSERT INTO transactions (price, shares, symbol, type, userid) VALUES (:price, :shares, :symbol, :transaction_type, :userid)",
                        price=current_price, shares=shares, symbol=symbol, transaction_type="BUY", userid=session["user_id"])
            # Update users cash
            db.execute("UPDATE users SET cash = :current WHERE id = :userid",
                        current=(current_cash[0]['cash'] - (current_price * shares)), userid=session["user_id"])
            flash('Bought!')
            return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    stocks = db.execute("SELECT type, symbol, shares, price, timestamp FROM transactions WHERE userid=:user_id",
                        user_id=session["user_id"])

    header = ['Status', 'Symbol', 'Shares', 'Price', 'Transacted']

    return render_template("history.html", header=header, stocks=stocks)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash('You were successfully logged in!')
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
    flash('You were successfully logged out!')
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")
    elif request.method == "POST":
        # Get the stock symbol from the form
        symbol = request.form.get("symbol")

        # Get the actual name, price and symbol of a stock
        if not lookup(symbol) or not symbol:
            return apology("no such symbol")
        else:
            result = lookup(symbol)
            result['price'] = usd(result['price'])
            flash('Quoted!')
            return render_template("quoted.html", quoted=result)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        # Get data from the form
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        rows = db.execute("SELECT username FROM users WHERE username=:user", user=username)

        # If username is already in database or input is blank
        if len(rows) == 1 or not username:
            return apology("invalid username")

        # If input is blank or passwords do not match
        if not password or not confirmation or password != confirmation:
            return apology("invalid password")

        # Insert username and hashed password into database
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
                    username=username, password=generate_password_hash(password))
        flash('Registered!')
        return render_template("register.html")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""

    if request.method == "GET":
        return render_template("password.html")
    elif request.method == "POST":
        # Get data from the form
        old_password = request.form.get("old")
        new_password = request.form.get("new")
        confirmation = request.form.get("confirmation")

        # If input is blank or passwords do not match
        if not old_password or not new_password or not confirmation or new_password != confirmation:
            return apology("invalid password")

        # If old password doesn't match with the one in the database
        rows = db.execute("SELECT hash FROM users WHERE id=:userid", userid=session["user_id"])

        if not check_password_hash(rows[0]['hash'], old_password):
            return apology("invalid password")

        # Insert username and hashed password into database
        db.execute("UPDATE users SET hash = :password WHERE id = :userid",
                    password=generate_password_hash(new_password), userid=session["user_id"])
        flash('You successfully changed your password!')
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        stocks = db.execute("SELECT symbol, SUM(shares) FROM transactions WHERE userid=:user_id GROUP BY symbol",
                            user_id=session["user_id"])

        stock = []

        for i in range(len(stocks)):
            if stocks[i]['SUM(shares)'] != 0:
                stock.append(stocks[i])

        stocks = stock

        symbols = []
        for i in range(len(stocks)):
            symbols.append(stocks[i]['symbol'])
        return render_template("sell.html", symbols=symbols)
    elif request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        stocks = db.execute("SELECT symbol, SUM(shares) FROM transactions WHERE userid=:user_id GROUP BY symbol",
                            user_id=session["user_id"])

        symbols = []
        for i in range(len(stocks)):
            symbols.append(stocks[i]['symbol'])

        for i in range(len(stocks)):
            if stocks[i]['symbol'] == symbol:
                number_of_shares = stocks[i]['SUM(shares)']

        if symbol not in symbols or not symbol:
            return apology("invalid or no symbol")
        elif shares < 1 or shares > number_of_shares:
            return apology("not enough shares")

        current_stock = lookup(symbol)
        current_price = current_stock['price']

        current_cash = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session["user_id"])

        # Create a log of the transaction
        db.execute("INSERT INTO transactions (price, shares, symbol, type, userid) VALUES (:price, :shares, :symbol, :transaction_type, :userid)",
                    price=current_price, shares=-shares, symbol=symbol, transaction_type="SELL", userid=session["user_id"])

        # Update users cash balance
        db.execute("UPDATE users SET cash = :current WHERE id = :userid",
                    current=(current_cash[0]['cash'] + (current_price * shares)), userid=session["user_id"])
        flash('Sold!')
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
