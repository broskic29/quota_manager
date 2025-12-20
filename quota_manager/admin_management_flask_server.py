from flask import Flask, request, render_template_string, jsonify, error
import sqlite3

import quota_manager.sql_management as sqlm

app = Flask(__name__)

DEFAULT_DB_PATH = "/var/lib/radius/freeradius.db"
DEFAULT_PASSWORD = "password"

new_user_form = """
<h2>Enter new user information:</h2>
<form method="post">
    Username: <input type="text" name="username" required><br><br>
    <input type="submit" value="Login">
</form>
{% if error %}
<p style="color:red;">{{ error }}</p>
{% endif %}
"""


# add another route called /api/admin that has buttons that take you to new_user,
# modify_user, usage overview pages
# Lock /api/admin pages behind a special admin password. Not a username, just a password.
# Can be done in flask alone. Use werkzeug
@app.route("/api/admin/new_user", methods=["GET", "POST"])
def create_user():

    if request.method == "POST":
        data = request.json
        username = data.get("username")
        password = DEFAULT_PASSWORD
        if not username:
            return (
                jsonify({"status": "error", "message": "Username required"}),
                400,
            )
        try:
            json_message = sqlm.insert_user_radius(username, password, DEFAULT_DB_PATH)
            return json_message
        except sqlite3.IntegrityError:
            return (
                jsonify({"status": "error", "message": "Username already exists"}),
                400,
            )
    return render_template_string(new_user_form, error=error)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
