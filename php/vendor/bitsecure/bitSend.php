<?php
/**
 * BitID PIN REQ.
 *
 * @package bitSend
 * @author Twistsmyth 
 * @license New BSD
 * @version 0.1
 */
include_once(dirname(__DIR__).'/autoload.php');
include_once(dirname(__DIR__).'/bitsecure/bitCypher.php');

define('ZERO_STORE', dirname(__DIR__).'/../../ZeroNet/data/1CEcrraaLQMM8k2Lf3U7MYMkxboV5BzV17/data/users/');//$file_db = new PDO('sqlite:myDatabase.sqlite3');

class bitSend
{

	private $pdo;

    /* Database related configuration */
	private $db_host = 'localhost'; //Database location 
	private $db_username = 'root'; //Database username
	private $db_password = ''; //Database password
	private $db_name = 'blocvotes'; //Database name
	private $db_table_name = 'users'; //Database table name (must be the same as the one used in create_table.sql)

    /* Path to PHPMailer, including a trailing slash (e.g. 'phpmailer/' if the files are located in the phpmailer folder);
    PasswordLessLogin needs 'class.phpmailer.php' and 'class.smtp.php' files (download from https://github.com/Synchro/PHPMailer);
    In case you want to use a solution other than PHPMailer, you will have to modify the 'send_login_email' function */

    /* SMTP email server related configuration */
	private $email_suffix = '@protonmail.com';
	private $email_host = 'mail.blocbit.org'; //'smtp.gmail.com';     //SMTP server
	private $email_port = 465; //SMTP port (leave zero for default)
	private $email_encryption = 'ssl'; //SMTP port (leave zero for default)
	private $email_username = 'secure@blocbit.org'; //'wastetimedev@gmail.com';		//SMTP username
	private $email_password = '2(=dlNcc78e*Ll#2HSh&7%:o478nkTfKg-w2uh:%4gZs~Wl5aD8G1K>@6r8Pg,5)6(:usgJ43[#~0m3g-gh&>'; //'Test123#@!';		//SMTP password
	private $email_from_email = 'secure@blocbit.org'; //Email address from which the login email will be sent
	private $email_from_name = 'Bloc.bit'; //Name from which the login email will be sent

    /* The subject of the login email */
	private $email_subject = 'Bit Pin';

    /* The base URL for the login page (e.g. http://example.com/login.php?code=); the generated code will be attached at the end automatically */
	private $login_base_url = 'https://localhost/index.php?code=';

    /* Seconds the login code is valid for; the default value is 600 seconds (10 minutes) */
	private $seconds_code_is_valid_for = 600;

    /* Will check if someone is requesting too many login codes within this time frame; the default value is 600 seconds (10 minutes) */
	private $seconds_to_check_for_spam = 600;

    /* Number of requests allowed per user and user ip within the allowed time; the default value is 3 */
	private $number_of_requests_per_user_and_ip = 3;

    /* A unique string to be used as salt when the login code is generated */
	private $salt = '';

    /* A set of error messages */
	private $error_messages = array('email_not_valid' => 'The email is not valid.',
                                    'user_not_registered' => 'The email does not belong to a register user.',
                                    'stop_spamming' => 'There were too many requests for your email or from your IP address, please try again in a few minutes.',
                                    'login_code_incorrect' => 'The login code is incorrect.',
                                    'login_code_used' => 'The login code was used before.',
                                    'login_code_expired' => 'The login code is expired.',
                                    'generic_error' => 'Something went wrong; please try again.');
	
    /* A set of success messages */
	private $success_messages = array('email_sent' => 'An email with a login URL was sent.',
                                      'valid_code' => 'The code is valid; proceed with login.');
									  
	//public $userid = md5(time() . '-'. rand(1,1000000000));								  

    public function __construct()
    {
        try
        {
            $this->pdo = new PDO("mysql:host=$this->db_host;dbname=$this->db_name", $this->db_username, $this->db_password);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_OBJ);
        }
        catch(PDOException $e)
        {
            $this->catchException($e->getMessage());
        }
    }
    /**
    * After an email validation, generates a unique login code, and sends it to the user's email
    *
    * @param string $email an email address e.g. "info@example.com"
    * @return array[boolean][string] boolean: indicating if the process was successfull; string: a message
    */
    public function request_bitpin($email, $bit, $pmkey)
    {

		$ip = $_SERVER["REMOTE_ADDR"];
		$generated_time = time();
				
		$login_code	= $this->generate_code($email, $generated_time);
		$login_code_salt = password_hash($login_code,PASSWORD_DEFAULT);
		//update mysql
		$record_updated = $this->update_login_record($bit, $generated_time, $login_code_salt, $ip);
		//update sqlite
		//$bit_updated = $this->update_bit_cipher($bit, $login_code);
		
		$iv = $login_code;
		
		//dev-- NB : todie
		$password = fopen(USER_DATABASE.'password','w');
		fwrite($password, $login_code);
		//----
		
		$db = file_get_contents(USER_DATABASE.$bit.'.json');
		$cypher = new bitCypher($iv);
		$edb = fopen(ZERO_STORE.$bit.'.bits','w');
		
		$php_encrypted      = $cypher->encrypt($db);
		fwrite($edb, $php_encrypted);
		
		$uedb = fopen(USER_DATABASE.$bit.'.bit','w');
		$esecret = file_get_contents(ZERO_STORE.$bit.'.bits');

		$php_decrypted      = $cypher->decrypt($esecret)  ;
		fwrite($uedb, $php_decrypted );
		

		$args['message'] = "please use ".$login_code." to login , this code will expire in 1 minute";

		//$pmkey = $_SERVER['DOCUMENT_ROOT'].'/.gnupg/A901425F602758973AB37B8988CBD46B386A6647.asc';

		$key = OpenPGP_Message::parse(OpenPGP::unarmor(file_get_contents($pmkey), 'PGP PUBLIC KEY BLOCK'));

		$plain_data  = new OpenPGP_LiteralDataPacket(
		$args['message'],
		array('format' => 'u', 'filename' => 'encrypted.gpg')
		);

		$encrypted = OpenPGP_Crypt_Symmetric::encrypt(
		$key,
		new OpenPGP_Message(array($plain_data))
		);

		$args['message'] = OpenPGP::enarmor($encrypted->to_bytes(), "PGP MESSAGE");

		//var_dump($args['message']);
		$emessage = str_replace("\r", "", $args['message']);
		
     	$transport = (new Swift_SmtpTransport($this->email_host, $this->email_port, $this->email_encryption))
		->setUsername($this->email_username)
		->setPassword($this->email_password); 
		$mailer = new Swift_Mailer($transport);
  		$message = (new Swift_Message($this->email_subject))
		->setFrom([$this->email_from_email => $this->email_from_name])
		->setTo($email)
		
		//->setBody('please use '.$login_code.' to login , this code will expire in 1 minute');
		->setBody($emessage);
		$result = $mailer->send($message);

        return $result;
    }


    /**
    * Generates a unique code based on the user's email and the time the request was made.
    *
    * @param string $email an email address e.g. "info@example.com".
    * @param int $generated_time
    * @return string the generated code
    */
    private function generate_code($email, $generated_time)
    {
        return sha1($email . $this->salt . $generated_time);

    }

	
	  private function update_login_record($bit, $generated_time, $login_code_salt, $ip)
    {
        try
        {
            $minimun_generated_time = $generated_time - $this->seconds_to_check_for_spam;

            $st = $this->pdo->prepare('INSERT INTO ' . $this->db_table_name . '
                                       (username, password, mailgen_at, ip, pin_used)
                                       VALUES (:username, :password, :generated_time, :ip, 0)
									   ON DUPLICATE KEY UPDATE
										password		= VALUES(password),
										mailgen_at	= VALUES(mailgen_at),
										ip				= VALUES(ip),
										pin_used		= 0');

            $st->bindParam(':username', $bit);
            $st->bindParam(':password', $login_code_salt);
            $st->bindParam(':generated_time', $generated_time);
            $st->bindParam(':ip', $ip);

            return $st->execute();
        }
        catch(PDOException $e)
        {
            $this->catchException($e->getMessage());
        }
    }

	
	/*	  private function update_bit_cipher($bit, $login_code)
    {
        try
        {
			//define('USER_DATABASE', $_SERVER['DOCUMENT_ROOT'].'/../.bvusers/');

		$file_db = new PDO('sqlite:'.USER_DATABASE.''.$bit.'.bit');
		//$file_db->exec("PRAGMA key = $login_code;");
		
			$sql = 'INSERT INTO '.$bit.'(
			pin) VALUES (
            :pin)';
                                          
			$stmt = $file_db->prepare($sql);
                                   
			$stmt->bindParam(':pin', $login_code, PDO::PARAM_STR);       
    											   				
            return $stmt->execute();
        }
        catch(PDOException $e)
        {
            $this->catchException($e->getMessage());
        }
    }
    /**
    * Sends an email containing the login code using Swift Mailer.
    *
    * @param string $email an email address e.g. "info@example.com".
    * @param string $login_code
    * @return boolean
    */
    public function uploadKey($bit, $filename, $file_basename, $file_ext, $filesize)
    {
	


        return $result;
		
	}
	
    private function catchException($message)
    {
        echo $message;
    }
}
?>