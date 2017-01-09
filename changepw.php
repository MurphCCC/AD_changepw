
<!--
modPassword() 修改帳號密碼
  1.驗證user舊密碼是否正確,使用ldap_bind
    但如果密碼過期，bind是會失敗的，所以要先確認密碼是否過期checkpwdexpired()
    如過期先把pwdlastset修改為0，才可以正常的使用ldap_bind來驗證舊密碼
  2.admin帳號必須在ou的最上層，否則無法搜尋所有的ou。
  3.如下面管理帳號不想使用domain administrator,該管理帳號請先在windows ad上面新增委派權限（修改密碼、讀取修改pwdlastset的權限）

checkpwdexpired()確認密碼是否為過期
modpwdlastset()修改pwdlastset值
-->


<?php
  $message = array();
  $message_css = "";

  function modPassword($user,$oldPassword, $newPassword, $newPasswordCnf){

    //your admin account in AD
    $adminid ="admin";
    $adminpw ="password";
    $domain = "dc.domain";
    $dn=  "dc=dc,dc=domain";
    $ldaprdn = $user.'@'.$domain;


    $ldapconn = ldap_connect($domain) or die("無法連接至 $domain");
    //以下兩行務必加上，否則 Windows AD 無法在不指定 OU 下搜尋
    ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);


    //check password expire from pwdlastset
    $checkpwdexpired=checkpwdexpired($user,$dn,$ldapconn,$adminid,$adminpw);
    if($checkpwdexpired==false){
      //if pwdlastset ==0 or expired, set pwdlastset to -1 
      //or you can't bind user to check the old password
      modpwdlastset($user,$dn,-1,$adminid,$adminpw,$ldapconn);
    }
    
    


    if($ldapconn)
    {
      $ldapbind = @ldap_bind($ldapconn, $ldaprdn, $oldPassword);
      //check user's oldpassword is correct.


      if($ldapbind){
        $filter = "(sAMAccountName=$user)";
        $result = @ldap_search($ldapconn, $dn, $filter);
        if($result==false) echo "ldap search failed. <br/>";
        else {


          $ldapadminbind=@ldap_sasl_bind( $ldapconn, NULL,$adminpw,'DIGEST-MD5',NULL,$adminid);
          //管理者要用sasl bind 才可以修改帳號
          //if you want to read and edit the domain directory in Windows AD, must use "sasl" to bind admin account.

          //取出帳號的所有資訊
          $entries = ldap_get_entries($ldapconn, $result);
          $userdn = $entries[0]["dn"];
          /* -----print all info from user---------------------------------
          echo $entries["count"]."entries returned\n";
          for($i=0; $i<=$entries["count"];$i++) {
            for ($j=0;$j<=$entries[$i]["count"];$j++) {
              echo $entries[$i][$j].": ".$entries[$i][$entries[$i][$j]][0]."\n<br>";
            }
          }
          */

          //---------password modify start -------------------------------
          if($newPassword != $newPasswordCnf ) {
            echo "::Your New passwords do not match!<br>";

            //if pwdlastset was set to -1 previously , must set it back to 0
            if($checkpwdexpired==false)
              modpwdlastset($user,$dn,0,$adminid,$adminpw,$ldapconn);
            
            ldap_close($ldapconn);
            return false;
          } 

          $modpassword =array();

          //at windows active directory ,the password attribute is "unicodePwd"
          $modpassword["unicodePwd"]=iconv("UTF-8", "UTF-16LE", '"' . $newPassword . '"');
          if(ldap_mod_replace($ldapconn,$userdn,$modpassword) == false ){
            $error = ldap_error($ldapconn);
            $errno = ldap_errno($ldapconn);
            echo "::E201 - Your password cannot be modified, please contact the administrator. <br>";
            echo "::$errno - $error";


            //if pwdlastset was set to -1 previously , must set it back to 0
            if($checkpwdexpired==false)
              modpwdlastset($user,$dn,0,$adminid,$adminpw,$ldapconn);
            
            ldap_close($ldapconn);
             
          } else {

            echo "The password for $user_id has been modified.Your new password is now fully Active.<br>";

          }
        }
      }
      else { //oldpassword error 
          echo "::Current Username or Password is wrong.<br>";
          //if pwdlastset was set to -1 previously , must set it back to 0
          if($checkpwdexpired==false)
            modpwdlastset($user,$dn,0,$adminid,$adminpw,$ldapconn);
          
          ldap_close($ldapconn);
           
      }
    }
    else{
        echo "::Connection Fail.<br>";
        if($checkpwdexpired==flase){
          modpwdlastset($user,$dn,0,$adminid,$adminpw,$ldapconn);
        }
        ldap_close($ldapconn);
        
    }

  }
  
  function checkpwdexpired($username,$ldapBase,$ldapconn,$domadlogin,$domadpw){
    if (!$ldapconn)
    die('Cannot Connect to LDAP server');

    $ldapBind = ldap_bind($ldapconn,$domadlogin,$domadpw);
    if (!$ldapBind){
      echo "::checkpwdexpired:Cannot Bind to LDAP server <br>";
      return false;
    }



    $attrs = array("samaccountname", "pwdlastset");
    $filter = "(samaccountname=".$username.")";
    $sr = ldap_search($ldapconn, $ldapBase, $filter, $attrs);
    $ent= ldap_get_entries($ldapconn,$sr);
    $pwdlastset=$ent[0]["pwdlastset"][0];
    if($pwdlastset == 0)
    {
      return false;
    }
    $sr1 = ldap_read($ldapconn, $ldapBase, 'objectclass=*', array('maxPwdAge'));
    $info = ldap_get_entries($ldapconn,$sr1);
    $maxpwdage =$info[0]['maxpwdage'][0];
//    echo "::checkpwdexpired maxpwdage : ".$maxpwdage."<br>";
    $pwdExpire = bcsub($pwdlastset, $maxpwdage);
    $timenow=time();
//    echo "time :". $timenow."   ".date("Y-m-d\TH:i:s\Z",$timenow)."<br>";
    $pwdexpireUnix = bcsub(bcdiv($pwdExpire, '10000000'), '11644473600'); //TO UNIX
//    echo "pwdexpire time :".$pwdexpireUnix."   ".date("Y-m-d\TH:i:s\Z",$pwdexpireUnix)."<br>";
    if($pwdexpireUnix<$timenow){
//        echo "::checkpwdexpired 密碼已過期<br>";
        return false;
    }


    return true;


  }


  function modpwdlastset($username,$ldapBase ,$pwdLastSetVal,$domadlogin,$domadpw,$ldapconn)
  {

    if (!$ldapconn)
       die('::modpwdlastset:Cannot Connect to LDAP server');

    $ldapBind = @ldap_bind($ldapconn,$domadlogin,$domadpw);
    if (!$ldapBind)
       die('::modpwdlastset:Cannot Bind to LDAP server');


    $attrs = array("sAMAccountName", "pwdlastset");
    $filter = "(sAMAccountName=$username)";
    $sr = @ldap_search($ldapconn, $ldapBase, $filter,$attrs);

    $ent= ldap_get_entries($ldapconn,$sr);
    $dn=$ent[0]["dn"];
    $userdata=array();
    $userdata["pwdlastset"][0]=$pwdLastSetVal;

    if(!ldap_modify($ldapconn, $dn, $userdata)){
      echo "<br>::modpwdlastset  modify failure <br>";
      echo "<br>::modpwdlastset ".ldap_error($ldapconn)."<br>";
      echo "<br>::modpwdlastset ".ldap_errno($ldapconn)."<br>";
      return false;
    }else{
      return true;
    }

  }
  


?>

<!DOCTYPE html>
<html>
<head>
<title> change password page </title>
</head>
<body>
<p> 更改您的密碼 </p>
<?php
  if(isset($_POST["submitted"])){
  //如果為submited 執行修改密碼

  modPassword($_POST['username'],$_POST['oldPassword'],$_POST['newPassword1'],$_POST['newPassword2']);

  }
?>
<form action="<?php print $_SERVER['PHP_SELF']; ?>" name="passwordMod" method="post">
        帳號： <input type="text" name="username"/><br/>
        舊密碼：<input type="password" name="oldPassword">
        新密碼：<input type="password" name="newPassword1">
        確認新密碼：<input type="password" name="newPassword2">
        <input name="submitted" type="submit" value="change password">
        </form>



</body>
</html>
