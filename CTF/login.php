<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
require_once($_SERVER['DOCUMENT_ROOT'] . '/include/include.php');
if ($ctf_login === 1) {
    header('Location: /dashboard.php');
    exit();
}
if ($_SERVER['REQUEST_METHOD'] == "POST" && $_POST['ftype'] == 'login') {
    $email = $_POST['email'];
    $pass = $_POST['pass'];
    if ($email == '' || $pass == '') {
        echo js_start . 'Please enter all the fields' . js_end;
    } else {
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $quer = $db->prepare("SELECT * FROM ctf_user WHERE email=?");
            $quer->bind_param('s', $email);
            if ($quer->execute()) {
                if ($get =
                    $quer->get_result()
                ) {
                    $st = $get->fetch_assoc();
                    if ($st['email_verify'] != 1) {
                        echo js_start . 'Please Verify your email first' . js_end;
                        header('Location:
/');
                        exit();
                    }
                    if (password_verify($pass, $st['pass'])) {
                        echo js_start .
                            'testing' . js_end;
                        $_SESSION['ctfaccess'] = array();
                        $_SESSION['ctfaccess']['access'] = true;
                        $_SESSION['ctfaccess']['name'] =
                            $st['name'];
                        $_SESSION['ctfaccess']['id'] = $st['id'];
                        $_SESSION['ctfaccess']['email'] = $st['email'];
                        header('Location:
/dashboard.php');
                    } else {
                        echo js_start . 'Wrong Credentials' . js_end;
                    }
                } else {
                    echo js_start . 'Wrong Credentials' . js_end;
                }
            } else {
                echo js_start .
                    'Sorry Some error occured' . js_end;
            }
        } else {
            echo js_start . 'Please enter
valid email' . js_end;
        }
    }
} elseif (
    $_SERVER['REQUEST_METHOD'] == "POST" &&
    $_POST['ftype'] == 'signup'
) {
    $name = $_POST['fname'];
    $email =
        $_POST['email'];
    $pass = $_POST['pass'];
    $conf_pass = $_POST['conf_pass'];
    if (
        $name == '' || $email == '' || $pass == '' || $conf_pass == ''
    ) {
        echo js_start
            . 'Please fill all the details' . js_end;
        exit();
    } else if (
        $pass !=
        $conf_pass
    ) {
        echo js_start . 'Password does not match' . js_end;
        exit();
    } else {
        if (!preg_match("/^[a-zA-Z ]+$/", $name)) {
            echo js_start . 'Please enter
valid name' . js_end;
        } else {
            if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $name = htmlspecialchars($name);
                $sec = randgen(50);
                $psw = password_hash(
                    $pass,
                    PASSWORD_BCRYPT
                );
                $quer = $db->prepare("INSERT INTO ctf_user (name, email, pass,
password) VALUES ( ?, ?, ?, ?)");
                $quer->bind_param(
                    'ssss',
                    $name,
                    $email,
                    $psw,
                    $sec
                );
                if ($quer->execute()) {
                    $to = $email;
                    $subject = 'Verify Your CTF
Account';
                    $message = 'Hello ' . $name . ' Thanks for registering with us.<br />Just
one more step to verify your account<br /><br /><a
  href="https://ctflab.in/verify.php?id=' . $email . '&s=' . $sec . '"
  >https://ctflab.in/verify.php?id=' . $email . '&s=' . $sec . '</a
>';
                    $headers = 'Content-type: text/html; charset=iso-8859-1' . "\r\n" . 'From:
support@ctflab.in' . "\r\n" . 'Reply-To: support@ctflab.in' . "\r\n" .
                        'X-Mailer: PHP/' . phpversion();
                    if (mail($to, $subject, $message, $headers)) {
                        echo js_start . 'Thx for registration. Please verify your email' . js_end;
                        header('Location: /');
                    } else {
                        echo js_start . 'Some error occured' . js_end;
                    }
                } else echo js_start . 'Sorry Some error occured' . js_end;
            } else {
                echo
                    js_start . 'Enter valid email' . js_end;
            }
        }
    }
}
