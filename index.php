<?php

if(isset($_COOKIE["444444444444444444"])

){

/*
If you put the whole webauthn directory in the www document root and put an index.php in there 
which just includes this file, it should then work. Alternatively set it as a link to this file.
*/
include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/webauthn/src/webauthn.php');

/* from https://github.com/2tvenom/CBOREncode :  */
include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/CBOREncode/src/CBOR/CBOREncoder.php');
include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/CBOREncode/src/CBOR/Types/CBORByteString.php');
include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/CBOREncode/src/CBOR/CBORExceptions.php');

//include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/BlocIDPinReq/BlocIDPinReq.php');

/* In this example, the user database is simply a directory of json files 
  named by their username (urlencoded so there are no weird characters 
  in the file names). For simplicity, it's in the HTML tree so someone 
  could look at it - you really, really don't want to do this for a 
  live system */
define('USER_DATABASE', dirname(dirname(__DIR__)).'/xampp/.bvusers');
if (! file_exists(USER_DATABASE)) {
  if (! @mkdir(USER_DATABASE)) {
    error_log('Cannot create user database directory - is the html directory writable by the web server? If not: "mkdir .users; chmod 777 .users"');
    die("cannot create .users - see error log");
  } 
}
session_start();

function oops($s){
  http_response_code(400);
  echo "{$s}\n";
  exit;
}

function userpath($username){
  $username = str_replace('.', '.', $username);
  return sprintf('%s/%s.json', USER_DATABASE, urlencode($username));
}

function getuser($username){
  $user = @file_get_contents(userpath($username));
  if (empty($user)) { oops('email not found'); }
  $user = json_decode($user);
  if (empty($user)) { oops('email not json decoded'); }
  return $user;
}


/* A post is an ajax request, otherwise display the page */
if (! empty($_POST)) {

  try {
  
    $webauthn = new davidearl\webauthn\WebAuthn($_SERVER['HTTP_HOST']);

    switch(TRUE){

    case isset($_POST['registerusername']):
      /* initiate the registration */
	 // if(isset($_POST['registerusername'])){ $username = $_POST['registerusername']; }
	 // if(isset($_POST['registeremail'])){ $email = $_POST['registeremail']; }
		$username = isset($_POST['registerusername']) ? $_POST['registerusername'] : '';
		//$nicname = isset($_POST['registernic']) ? $_POST['registernic'] : '';
      
      $userid = md5(time() . '-'. rand(1,1000000000));

      if (file_exists(userpath($username))) {
        oops("BlocID '{$username}' already exists");
      }

      /* Create a new user in the database. In principle, you can store more 
         than one key in the user's webauthnkeys,
         but you'd probably do that from a user profile page rather than initial 
         registration. The procedure is the same, just don't cancel existing 
         keys like this.*/
      file_put_contents(userpath($username), json_encode([	'email'=> $username,
															//'nicname'=> $nicname,	  
															'id'=> $userid,
															'webauthnkeys' => $webauthn->cancel()]));
      $_SESSION['username'] = $username;
      $j = ['challenge' => $webauthn->prepare_challenge_for_registration($username, $userid)];
      break;

    case isset($_POST['register']):
      /* complete the registration */
      if (empty($_SESSION['username'])) { oops('username not set'); }
      $user = getuser($_SESSION['username']);

      /* The heart of the matter */
      $user->webauthnkeys = $webauthn->register($_POST['register'], $user->webauthnkeys);

      /* Save the result to enable a challenge to be raised agains this 
         newly created key in order to log in */
      file_put_contents(userpath($user->email), json_encode($user));
	  
	   /* email the pin to the email in form */
	  
	  //$blocPin = new BlocIDPinReq();
	  //$email = getuser($_SESSION['username']) ? $_SESSION['username'] : '';
	  //$blocPin->request_login_code($email);
      
	  $j = 'ok';
      
      break;

    case isset($_POST['loginusername']):
      /* initiate the login */
      $username = $_POST['loginusername'];
      $user = getuser($username);
	  $_SESSION['loginname'] = $user->email;
	  
      /* note: that will emit an error if username does not exist. That's not 
         good practice for a live system, as you don't want to have a way for
         people to interrogate your user database for existence */

      $j['challenge'] = $webauthn->prepare_for_login($user->webauthnkeys);
      break;

    case isset($_POST['login']):
      /* authenticate the login */
      if (empty($_SESSION['loginname'])) { oops('username not set'); }
      $user = getuser($_SESSION['loginname']);

      if (! $webauthn->authenticate($_POST['login'], $user->webauthnkeys)) {
        http_response_code(401);
        echo 'failed to authticate with that key';
        exit;
      }
	  
	  $blocPin = new BlocIDPinReq();
		$email = 'va1idus@hotmail.com' ;
	  $blocPin->request_login_code($email);

      $j = 'ok';
      
      break;

    default:
      http_response_code(400);
      echo "unrecognized POST\n";
      break;
    }    

  } catch(Exception $ex) {
    oops($ex->getMessage());
  }
    
  header('Content-type: application/json');
  echo json_encode($j);
  exit;
}   
?>
<!doctype html>
<html lang="en" class="fullscreen-bg">
<head>
	<title>Register | BlocID</title>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0">
	<!-- VENDOR CSS -->
	<link rel="stylesheet" href="/assets/css/bootstrap.min.css">
	<link rel="stylesheet" href="/assets/vendor/font-awesome/css/font-awesome.min.css">	
	<!-- MAIN CSS -->
	<link rel="stylesheet" href="/assets/css/main.css">
	<!-- GOOGLE FONTS -->
	<link href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,700" rel="stylesheet">
	<!-- ICONS -->
	<link rel="apple-touch-icon" sizes="76x76" href="/assets/img/apple-icon.png">
	<link rel="icon" type="image/png" sizes="96x96" href="/assets/img/favicon.png">
</head>
<body>
<div id="background">
    <img src="/assets/img/login-bk.jpg" class="stretch" alt="" />
</div>
<!-- WRAPPER -->
<div id="wrapper">
	<div class="vertical-align-wrap">
		<div class="vertical-align-middle">
			<div class="auth-box ">
				<div class="left">
					<div class="content">
						<div class="header">
							<div class="logo text-center"><img src="/assets/img/logo-dark.png" alt="Logo"></div>
							<p class="lead">Bloc Registration</p>
						</div>
                        <div class='cerror'></div>
						<div class='cdone'></div> 	
						
							<form id='iregisterform' class="form-auth-small" action='/' method='POST'>
							<div class="form-group">
							<input type='email' class="form-control" name='registerusername' placeholder='Email '>
							</div>
							<input type='submit' class="btn btn-primary btn-lg btn-block" value='Register'>
							</form>
												
							<div class='cdokey' id='iregisterdokey'>
							press button on key
							</div>
							<div class="bottom">
							<span class="helper-text"><i class="fa fa-lock"></i> <a href="/" id="home">Login!</a></span>&nbsp;
							<span class="helper-text"><i class="fa fa-chain"></i> <a href="/" id="burn">Pin Req!</a></span>
							</div>							
					</div>
				</div>
				<div class="right">
					<div class="overlay"></div>
					<div class="content text">
						<div class="lead"><h1>Anonymous Voting for a Decentralised Web</h1></div>
						<br/>
						<p class="lead">A Hardware Key and Secure Email address are required to vote</p>
						<br/>
						<p class="lead">Purchase a Secure Opensource Hardware Key<a href="https://solokeys.com" target="_blank"> Here</a></p>
						<br/>
						<p class="lead">Create an Encrypted Email Address <a href="https://protonmail.com" target="_blank"> Here</a></p>
						<br/>
						<p class="lead"><a href="https://" target="_blank"> Why these ?</a></p>
					</div>
				</div>
				<div class="clearfix"></div>
			</div>
		</div>
	</div>
</div>

<!-- only for the example, the webauthn js does not need jquery itself 

<script>
$(document).ready(function() {
     var CookieGet = Cookies.get('444444444444444444');
     if (CookieGet != null) {
          // Hide the element here.
          $('.ccontent').hide();
     }
 });
 </script>
 -->
<script src="/assets/vendor/jquery/jquery.min.js"></script>	
<script src="/assets/vendor/bootstrap/js/bootstrap.min.js"></script>	
	<script src='/assets/scripts/webauthnregister.js'></script>
	<script src='/assets/scripts/webauthnauthenticate.js'></script>
	<script src='/assets/scripts/jscookie.js'></script>
<script>
$("#home").on("click", function () {
    Cookies.remove('444444444444444444','444444444444444444');
});
 </script>
 <script>
$("#burn").on("click", function () {
    Cookies.set('55555','55555');
	Cookies.remove('444444444444444444','444444444444444444');

});
 </script>
 <script>
$("#home").on("click", function () {
    Cookies.remove('55555','55555');
});
 </script>
<script>
  $(function(){

	$('#iregisterform').submit(function(ev){
		var self = $(this);
		ev.preventDefault();
		$('.cerror').empty().hide();
		
		$.ajax({url: '/',
				method: 'POST',
				data: {registerusername: self.find('[name=registerusername]').val(), registernic: self.find('[name=registernic]').val()},
				dataType: 'json',
				success: function(j){
					$('#iregisterform,#iregisterdokey').toggle();
					/* activate the key and get the response */
					webauthnRegister(j.challenge, function(success, info){
						if (success) {
							$.ajax({url: '/',
									method: 'POST',
									data: {register: info},
									dataType: 'json',
									success: function(j){
										$('#iregisterform,#iregisterdokey').toggle();
										$('.cdone').text("Pin Req Completed Successfully, On Route To Email").show();
										setTimeout(function(){ $('.cdone').hide(300); }, 2000);
										Cookies.remove('444444444444444444');
										document.location.href="/";				
									},
									error: function(xhr, status, error){
										$('.cerror').text("Pin Req Failed: "+error+": "+xhr.responseText).show();
									}
								   });
						} else {
							$('.cerror').text(info).show();
						}
					});
				},

				error: function(xhr, status, error){
					$('#iregisterform').show();
					$('#iregisterdokey').hide();
					$('.cerror').text("Could not initiate Key Communication: "+error+": "+xhr.responseText).show();
				}
			   });
	});
	
});

</script>
    <!-- END WRAPPER -->
</body>
</html>
<?php
}
else if (isset($_COOKIE["55555"])){

/*
If you put the whole webauthn directory in the www document root and put an index.php in there 
which just includes this file, it should then work. Alternatively set it as a link to this file.
*/
include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/webauthn/src/webauthn.php');

/* from https://github.com/2tvenom/CBOREncode :  */
include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/CBOREncode/src/CBOR/CBOREncoder.php');
include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/CBOREncode/src/CBOR/Types/CBORByteString.php');
include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/CBOREncode/src/CBOR/CBORExceptions.php');

//include_once($_SERVER['DOCUMENT_ROOT'].'/../app/Controllers/Auth/MailController.php');

include_once($_SERVER['DOCUMENT_ROOT'].'/../vendor/BlocIDPinReq/BlocIDPinReq.php');

/* In this example, the user database is simply a directory of json files 
  named by their username (urlencoded so there are no weird characters 
  in the file names). For simplicity, it's in the HTML tree so someone 
  could look at it - you really, really don't want to do this for a 
  live system */
define('USER_DATABASE', dirname(dirname(__DIR__)).'/xampp/.bvusers');
if (! file_exists(USER_DATABASE)) {
  if (! @mkdir(USER_DATABASE)) {
    error_log('Cannot create user database directory - is the html directory writable by the web server? If not: "mkdir .users; chmod 777 .users"');
    die("cannot create .users - see error log");
  } 
}
session_start();

function oops($s){
  http_response_code(400);
  echo "{$s}\n";
  exit;
}

function userpath($username){
  $username = str_replace('.', '.', $username);
  return sprintf('%s/%s.json', USER_DATABASE, urlencode($username));
}

function getuser($username){
  $user = @file_get_contents(userpath($username));
  if (empty($user)) { oops('user not found'); }
  $user = json_decode($user);
  if (empty($user)) { oops('user not json decoded'); }
  return $user;
}


/* A post is an ajax request, otherwise display the page */
if (! empty($_POST)) {

  try {
  
    $webauthn = new davidearl\webauthn\WebAuthn($_SERVER['HTTP_HOST']);

    switch(TRUE){

    case isset($_POST['registerusername']):
      /* initiate the registration */
	 // if(isset($_POST['registerusername'])){ $username = $_POST['registerusername']; }
	 // if(isset($_POST['registeremail'])){ $email = $_POST['registeremail']; }
		$username = isset($_POST['registerusername']) ? $_POST['registerusername'] : '';
		//$email = isset($_POST['registeremail']) ? $_POST['registeremail'] : '';
      
      $userid = md5(time() . '-'. rand(1,1000000000));

      if (file_exists(userpath($username))) {
        oops("BlocID '{$username}' already exists");
      }

      /* Create a new user in the database. In principle, you can store more 
         than one key in the user's webauthnkeys,
         but you'd probably do that from a user profile page rather than initial 
         registration. The procedure is the same, just don't cancel existing 
         keys like this.*/
      file_put_contents(userpath($username), json_encode([	'email'=> $username,														 
															'id'=> $userid,
															'webauthnkeys' => $webauthn->cancel()]));
      $_SESSION['username'] = $username;
      $j = ['challenge' => $webauthn->prepare_challenge_for_registration($username, $userid)];
      break;

    case isset($_POST['register']):
      /* complete the registration */
      if (empty($_SESSION['username'])) { oops('username not set'); }
      $user = getuser($_SESSION['username']);

      /* The heart of the matter */
      $user->webauthnkeys = $webauthn->register($_POST['register'], $user->webauthnkeys);

      /* Save the result to enable a challenge to be raised agains this 
         newly created key in order to log in */
      file_put_contents(userpath($user->name), json_encode($user));
      $j = 'ok';
      
      break;

    case isset($_POST['loginusername']):
      /* initiate the login */
      $username = $_POST['loginusername'];
      $user = getuser($username);
	  $_SESSION['loginname'] = $user->email;
      /* note: that will emit an error if username does not exist. That's not 
         good practice for a live system, as you don't want to have a way for
         people to interrogate your user database for existence */

      $j['challenge'] = $webauthn->prepare_for_login($user->webauthnkeys);
      break;

    case isset($_POST['login']):
      /* authenticate the login */
      if (empty($_SESSION['loginname'])) { oops('username not set'); }
      $user = getuser($_SESSION['loginname']);

      if (! $webauthn->authenticate($_POST['login'], $user->webauthnkeys)) {
        http_response_code(401);
        echo 'failed to authticate with that key';
        exit;
      }
	  
		//$username = getuser($_SESSION['username']) ? $_SESSION['username'] : '';
		//unlink(userpath($username));
		 //$blocPin = new MailController();
		 $blocPin = new BlocIDPinReq();
	  $email = getuser($_SESSION['loginname']) ? $_SESSION['loginname'] : '';
	  $blocPin->request_login_code($email);
		
      $j = 'ok';
      
      break;

    default:
      http_response_code(400);
      echo "unrecognized POST\n";
      break;
    }    

  } catch(Exception $ex) {
    oops($ex->getMessage());
  }
    
  header('Content-type: application/json');
  echo json_encode($j);
  exit;
}   
?>
<!doctype html>
<html lang="en" class="fullscreen-bg">
<head>
	<title>Register | BlocID</title>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0">
	<!-- VENDOR CSS -->
	<link rel="stylesheet" href="/assets/css/bootstrap.min.css">
	<link rel="stylesheet" href="/assets/vendor/font-awesome/css/font-awesome.min.css">	
	<!-- MAIN CSS -->
	<link rel="stylesheet" href="/assets/css/main.css">
	<!-- GOOGLE FONTS -->
	<link href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,700" rel="stylesheet">
	<!-- ICONS -->
	<link rel="apple-touch-icon" sizes="76x76" href="/assets/img/apple-icon.png">
	<link rel="icon" type="image/png" sizes="96x96" href="/assets/img/favicon.png">
</head>
<body>
<div id="background">
    <img src="/assets/img/login-bk.jpg" class="stretch" alt="" />
</div>
<!-- WRAPPER -->
<div id="wrapper">
	<div class="vertical-align-wrap">
		<div class="vertical-align-middle">
			<div class="auth-box ">
				<div class="left">
					<div class="content">
						<div class="header">
							<div class="logo text-center"><img src="/assets/img/logo-dark.png" alt="Logo"></div>
							<p class="lead">Bloc Access</p>
						</div>
                        <div class='cerror'></div>
						<div class='cdone'></div> 	
											
							<form id='iloginform'  class="form-auth-small" action='/' method='POST'>
							<div class="form-group">
							<input type='email' class="form-control" name='loginusername' placeholder='Email'>
							</div>
							<input type='submit' class="btn btn-primary btn-lg btn-block" value='Pin Req!'>
							</form>
							
							<div class='cdokey' id='iregisterdokey'>
							press button on key
							</div>
							<div class="bottom">
							<span class="helper-text"><i class="fa fa-lock"></i> <a href="/" id="home">Login!</a></span>&nbsp;
							<span class="helper-text"><i class="fa fa-shield"></i> <a href="../" id="reg">Register!</a></span>
							</div>							
					</div>
				</div>
				<div class="right">
					<div class="overlay"></div>
					<div class="content text">
						<div class="lead"><h1>Anonymous Voting for a Decentralised Web</h1></div>
						<br/>
						<p class="lead">A Hardware Key and Secure Email address are required to vote</p>
						<br/>
						<p class="lead">Purchase a Secure Opensource Hardware Key<a href="https://solokeys.com" target="_blank"> Here</a></p>
						<br/>
						<p class="lead">Create an Encrypted Email Address <a href="https://protonmail.com" target="_blank"> Here</a></p>
						<br/>
						<p class="lead"><a href="https://" target="_blank"> Why these ?</a></p>
					</div>
				</div>
				<div class="clearfix"></div>
			</div>
		</div>
	</div>
</div>

<!-- only for the example, the webauthn js does not need jquery itself 

<script>
$(document).ready(function() {
     var CookieGet = Cookies.get('444444444444444444');
     if (CookieGet != null) {
          // Hide the element here.
          $('.ccontent').hide();
     }
 });
 </script>
 -->
<script src="/assets/vendor/jquery/jquery.min.js"></script>	
<script src="/assets/vendor/bootstrap/js/bootstrap.min.js"></script>	
<script src='/assets/scripts/webauthnregister.js'></script>
<script src='/assets/scripts/webauthnauthenticate.js'></script>
<script src='/assets/scripts/jscookie.js'></script>
<script>
$("#reg").on("click", function () {
    Cookies.remove('55555','55555');
	Cookies.set('444444444444444444','444444444444444444');
});
 </script>
 <script>
$("#home").on("click", function () {
    Cookies.remove('55555','55555');
});
 </script>
<script>
  $(function(){

	$('#iloginform').submit(function(ev){
		var self = $(this);
		ev.preventDefault();
		$('.cerror').empty().hide();
		
		$.ajax({url: '/',
				method: 'POST',
				data: {loginusername: self.find('[name=loginusername]').val()},
				dataType: 'json',
				success: function(j){
					$('#iloginform,#ilogindokey').toggle();
					/* activate the key and get the response */
					webauthnAuthenticate(j.challenge, function(success, info){
						if (success) {
							$.ajax({url: '/',
									method: 'POST',
									data: {login: info},
									dataType: 'json',
									success: function(j){
										$('#iloginform,#ilogindokey').toggle();
										$('.cdone').text("Pin Sent").show();
										$('#iloginform,#iemailform').toggle();
										setTimeout(function(){ $('.cdone').hide(500); }, 2000);		
										Cookies.remove('55555');
										document.location.href="/";
									},
									error: function(xhr, status, error){
										$('.cerror').text("Pin Req Failed: "+error+": "+xhr.responseText).show();
									}
								   });
						} else {
							$('.cerror').text(info).show();
						}
					});
				},
				
				error: function(xhr, status, error){
					$('#iloginform').show();
					$('#ilogindokey').hide();
					$('.cerror').text("Pin Not Sent: "+error+": "+xhr.responseText).show();
				}
			   });
	});
	
});

</script>
    <!-- END WRAPPER -->
</body>
</html>	

<?php
}
else{
	
require __DIR__ . '\..\bootstrap\app.php';
$app->run();

}
   