login_form = """
<div class="form-container">
    <h2>Wi-Fi Login</h2>

    <form method="post">
        <label>
            Username:
            <input type="text" name="username" required placeholder="Enter your username">
        </label>

        <label>
            Password:
            <input type="password" name="password" required placeholder="Enter your password">
        </label>

        <input type="submit" value="Login">
    </form>

    {% if message %}
    <p class="message">{{ message }}</p>
    {% endif %}

    {% if error %}
    <p class="error-message">{{ error }}</p>
    {% endif %}
</div>

<style>
.form-container {
    max-width: 400px;
    margin: 40px auto;
    padding: 20px 25px;
    border-radius: 10px;
    background-color: #f8f9fa;
    box-shadow: 0 6px 12px rgba(0,0,0,0.1);
    font-family: Arial, sans-serif;
}

h2 {
    text-align: center;
    color: #333;
    margin-bottom: 20px;
}

form label {
    display: block;
    margin-bottom: 15px;
    font-weight: 500;
    color: #444;
}

form input[type="text"],
form input[type="password"] {
    width: 100%;
    padding: 10px 12px;
    font-size: 1rem;
    margin-top: 5px;
    border: 1px solid #ccc;
    border-radius: 6px;
    box-sizing: border-box;
}

form input[type="submit"] {
    width: 100%;
    padding: 10px 12px;
    font-size: 1rem;
    background-color: #007bff;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    transition: background-color 0.2s ease;
}

form input[type="submit"]:hover {
    background-color: #0056b3;
}

.message {
    color: black;
    margin-top: 15px;
    text-align: center;
    font-size: 0.9rem;
}

.error-message {
    color: red;
    margin-top: 15px;
    text-align: center;
    font-size: 0.9rem;
}

</style>

"""

user_dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Welcome, {{ username }}.</title>

<!-- Font Awesome for icons -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" integrity="sha512-..." crossorigin="anonymous" referrerpolicy="no-referrer" />

<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 0;
        padding: 0;
        background: #f4f6f8;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
    }

    .container {
        text-align: center;
        background: white;
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        width: 90%;
        max-width: 400px;
    }

    h1 {
        margin-bottom: 1.5rem;
        color: #333;
        font-size: 2rem;
    }

    .usage {
        font-size: 2rem;
        margin: 2rem 0;
        font-weight: bold;
        color: #007bff;
    }

    .quota_message {
        font-size: 1rem;
        margin: 2rem 0;
        font-weight: bold;
        color: #007bff;
    }

    .button-grid {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }

    .button-grid a {
        text-decoration: none;
    }

    .button-grid button {
        width: 100%;
        padding: 1rem;
        font-size: 1rem;
        font-weight: bold;
        color: white;
        background-color: #007bff;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        transition: background-color 0.2s ease;
    }

    .button-grid button:hover {
        background-color: #0056b3;
    }

    .bottom-buttons {
        display: flex;
        gap: 1rem;
        margin-top: 2rem;
    }

    .bottom-buttons button {
        flex: 1;
    }

    @media (min-width: 500px) {
        .button-grid button {
            flex-direction: row;
        }
    }

    .message {
        color: black;
        margin-top: 1.5rem;
        text-align: center;
        font-size: 0.9rem;
    }

    .error-message {
        color: red;
        margin-top: 15px;
        text-align: center;
        font-size: 0.9rem;
    }

</style>
</head>
<body>
    <div class="container">
        <h1>User Dashboard</h1>

        <!-- Dynamic daily usage -->
        <div class="usage">
            {{ daily_usage | round(2) }} {{ usage_byte_unit }} / {{ quota | round(2) }} {{ quota_byte_unit }}
        </div>

        <!-- Quota message -->
        <div class="quota_message" style="color: {% if exceeds_quota %}red{% else %}black{% endif %}; font-size: {% if exceeds_quota %}1rem{% else %}0.5rem{% endif %};">
            {% if exceeds_quota %}
                You are over quota! Data will reset at 24:00.
            {% else %}
                You are under quota.
            {% endif %}
        </div>

        <div class="bottom-buttons">
            <a href="/user/{{ username }}/logout"><button><i class="fa-solid fa-sign-out-alt"></i> Log Out</button></a>
            <a href="/user/{{ username }}/change_password"><button><i class="fa-solid fa-key"></i> Change Password</button></a>
        </div>

        {% if message %}
        <p class="message">{{ message }}</p>
        {% endif %}

        {% if error %}
        <p class="error-message">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

password_change_form = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Change Password</title>
<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #f4f6f8;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        margin: 0;
    }
    .container {
        background: white;
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        width: 90%;
        max-width: 400px;
        text-align: center;
    }
    h1 {
        margin-bottom: 1.5rem;
        color: #333;
    }
    form {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }
    input {
        padding: 0.8rem;
        font-size: 1rem;
        border: 1px solid #ccc;
        border-radius: 8px;
    }
    button {
        padding: 1rem;
        font-size: 1rem;
        font-weight: bold;
        color: white;
        background-color: #007bff;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        transition: background-color 0.2s ease;
    }
    button:hover {
        background-color: #0056b3;
    }
    .error {
        color: red;
        font-weight: bold;
        margin-bottom: 1rem;
    }
</style>
</head>
<body>
    <div class="container">
        <h1>Change Password</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="post">
            <input type="password" name="current_password" placeholder="Current Password" required>
            <input type="password" name="new_password" placeholder="New Password" required>
            <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
            <button type="submit">Change Password</button>
        </form>
    </div>
</body>
</html>
"""
