<?php
/**
 * django auth backend
 *
 * @author    Andreas Gohr <andi@splitbrain.org>
 * @author    Michael Luggen <michael.luggen at unifr.ch>
 * @author    Robert Czechowski <zgtm at zgtm.de>
 */

define('DOKU_AUTH', dirname(__FILE__));
define('AUTH_USERFILE',DOKU_CONF.'users.auth.php');

class auth_plugin_authdjango extends DokuWiki_Auth_Plugin  {

    var $dbh = null; // db handle

    /**
     * Constructor.
     *
     * Sets additional capabilities and config strings
     * @author    Michael Luggen <michael.luggen at rhone.ch>
     * @author    Robert Czechowski <zgtm at zgtm.de>
     */
    public function __construct()
    {
        parent::__construct();

        global $config_cascade;
        global $dbh;

        $this->cando['external'] = true;
        $this->cando['getGroups'] = true;

        $this->cando['logout'] = !empty($this->getConf('logoff_uri'));

        try {
            // Connecting, selecting database
            if ($this->getConf('protocol') == 'sqlite') {
                $this->dbh = new PDO('sqlite:' . $this->getConf('server'));
            }
            else {
                $this->dbh = new PDO($this->getConf('protocol') . ':host=' . $this->getConf('server') . ';dbname=' . $this->getConf('db'), $this->getConf('user'), $this->getConf('password'));
            }
        } catch (PDOException $e) {
            msg("Can not connect to database!", -1);
            dbg($e);
            $this->success = false;
        }
        $this->success = true;
    }


    function trustExternal($user,$pass,$sticky=false){
        global $USERINFO;
        global $conf;
        global $dbh;

        $sticky ? $sticky = true : $sticky = false; //sanity check

        /**
         * Just checks against the django sessionid variable,
         * gets user info from django-database
         */

        if (isset($_COOKIE['sessionid']) && $this->dbh) {

            $s_id =  $_COOKIE['sessionid'];

            // Look the cookie up in the db
            $query = 'SELECT session_data FROM django_session WHERE session_key=' . $this->dbh->quote($s_id) . ' LIMIT 1;';
            $result = $this->dbh->query($query) or die('Query failed1: ' . $this->dbh->errorInfo());
            $ar = $result->fetch(PDO::FETCH_ASSOC);
            $session_data = $ar['session_data'];

            // TODO: $session_data can now be empty if the session does not exist in database, handle correctly instead of just dying
            if (strlen($session_data) == 0) {
                return false;
            }

            $compressed = false;

            if (str_contains($session_data, ":")) {
                // New django session encoding since django 4
                if ($session_data[0] == '.') {
                    $compressed = true;
                    $session_data = substr($session_data, 1);
                }

                $session_json = base64_decode(strtr(preg_split('/:/', $session_data, 2)[0], "-_", "+/"), true);

                if ($compressed) {
                       $session_json = zlib_decode($session_json);
                }

            } else {
                // Old django session enconding until django 3
                // Decoding the session data:

                $session_json = preg_split('/:/', base64_decode($session_data), 2)[1];
            }
            $userid = json_decode($session_json, true)['_auth_user_id'];
            $query2 = 'SELECT username, first_name, last_name, email, is_superuser, is_staff FROM auth_user WHERE id=' . $this->dbh->quote($userid) . ' LIMIT 1;';

            $result2 = $this->dbh->query($query2) or die('Query failed2: ' . print_r($this->dbh->errorInfo()));
            $user = $result2->fetch(PDO::FETCH_ASSOC);

            $username =  $user['username'];
            $userfullname = $user['first_name'] . " " . $user['last_name'];
            $useremail = $user['email'];

            // okay we're logged in - set the globals
            $groups = $this->_getUserGroups($username);

            $USERINFO['name'] = $username;
            $USERINFO['pass'] = '';
            $USERINFO['mail'] = $useremail;

            if (($user['is_superuser'] && $this->getConf('admin_admin') == 1)
                || ($user['is_staff'] && $this->getConf('staff_admin') == 1))
            {
                $groups[] = 'admin';
            } else {
                foreach ($this->getConf('groups_admin') as $admin_group) {
                    foreach ($groups as $group) {
                        if ($group == $admin_group && $group != "") {
                            $groups[] = 'admin';
                            break 2; // break both for loops
                        }
                    }
                }
            }
            $USERINFO['grps'] = $groups;

            $_SERVER['REMOTE_USER'] = $username;

            $_SESSION[DOKU_COOKIE]['auth']['user'] = $username;
            $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;

            return true;
        }
        return false;
    }

    function _getUserGroups($user){
        $query = 'SELECT auth_group.name FROM auth_user, auth_user_groups, auth_group where auth_user.username = ' . $this->dbh->quote($user) . ' AND auth_user.id = auth_user_groups.user_id AND auth_user_groups.group_id = auth_group.id;';

        $result = $this->dbh->query($query) or die('Query failed3: ' . $this->dbh->errorInfo());

        $groups = [];
        foreach ($result as $row) {
            $groups[] = $row[0];
        };

        if (!in_array("user", $groups)) {
            $groups[] = "user";
        }

        return $groups;
    }


    function retrieveGroups($start=0,$limit=0){
        $query = 'SELECT auth_group.name FROM auth_group';

        $result = $this->dbh->query($query) or die('Query failed4: ' . $this->dbh->errorInfo());

        $groups = [];
        foreach ($result as $row) {
            $groups[] = $row[0];
        };

        if (!in_array("user", $groups)) {
            $groups[] = "user";
        }

        if (!in_array("admin", $groups)) {
            $groups[] = "admin";
        }

        return $groups;
    }


    function logOff() {
        header("Location: " . $this->getConf('logoff_uri'));
        die();
    }


    function __destruct() {
        $this->dbh = null;
    }
}
