<?php
session_start();
if(!isset($_SESSION["username"])){
    header("location:index.html");

}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Page</title>
</head>
<body>
    <h1>Welcome, User!</h1> <?php echo $_SESSION["username"] ?>
    <a href="logout.php">logout</a>

</body>
</html>
