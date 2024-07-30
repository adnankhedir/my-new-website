<?php
$servername = "localhost";
$db_username = "root";
$db_password = "";
$dbname = "mynewwebsite";

session_start();

// Create connection
$conn = new mysqli($servername, $db_username, $db_password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $role = $_POST['role'];

    // Debugging output
    echo "Username: " . htmlspecialchars($username) . "<br>";
    echo "Role: " . htmlspecialchars($role) . "<br>";

    // Prepare and bind
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ? AND role = ?");
    if ($stmt) {
        $stmt->bind_param("ss", $username, $role);

        // Execute the statement
        $stmt->execute();

        // Bind result variables
        $stmt->bind_result($id, $db_password);

        // Fetch value
        if ($stmt->fetch()) {
            echo "Database Password: " . htmlspecialchars($db_password) . "<br>";
            if ($password == $db_password) {
                // Login successful, redirect based on role
                if ($role == 'manager') {
                    $_SESSION["username"]=$username;
                    header("Location: manager_page.php");
                } elseif ($role == 'admin') {
                    $_SESSION["username"]=$username;
                    header("Location: admin_page.php");
                } elseif ($role == 'user') {
                    $_SESSION["username"]=$username;
                    header("Location: user_page.php");
                }
                exit(); // Ensure no further code is executed
            } else {
                echo "Login failed. Incorrect password.";
            }
        } else {
            echo "Login failed. Invalid username or role.";
        }

        // Close statement
        $stmt->close();
    } else {
        echo "Error preparing statement: " . $conn->error;
    }
}

// Close connection
$conn->close();
?>
