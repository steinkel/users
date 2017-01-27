<?php
/**
 * Copyright 2010 - 2015, Cake Development Corporation (http://cakedc.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright 2010 - 2015, Cake Development Corporation (http://cakedc.com)
 * @license MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

namespace CakeDC\Users\Controller\Component;

use Cake\Network\Exception\NotFoundException;
use CakeDC\Users\Auth\Social\Mapper\Twitter;
use CakeDC\Users\Controller\Traits\CustomUsersTableTrait;
use CakeDC\Users\Exception\AccountNotActiveException;
use CakeDC\Users\Exception\BadConfigurationException;
use Cake\Controller\Component;
use Cake\Core\Configure;
use Cake\Event\Event;
use Cake\Event\EventManager;
use Cake\Network\Request;
use Cake\Routing\Exception\MissingRouteException;
use Cake\Routing\Router;
use Cake\Utility\Hash;
use CakeDC\Users\Exception\MissingEmailException;
use CakeDC\Users\Exception\UserNotActiveException;

class LoginComponent extends Component
{
    use CustomUsersTableTrait;

    public $components = [
        'Auth',
        'Flash',
    ];

    public function beforeFilter(Event $event)
    {
        $this->Auth->allow([
            'login',
            'twitterLogin',
            'verify'
        ]);
    }

    /**
     * Do twitter login
     *
     * @return mixed|void
     */
    public function twitterLogin()
    {
        $this->_registry->getController()->autoRender = false;
        $server = new Twitter([
            'identifier' => Configure::read('OAuth.providers.twitter.options.clientId'),
            'secret' => Configure::read('OAuth.providers.twitter.options.clientSecret'),
            'callbackUri' => Configure::read('OAuth.providers.twitter.options.redirectUri'),
        ]);
        $oauthToken = $this->request->query('oauth_token');
        $oauthVerifier = $this->request->query('oauth_verifier');
        if (!empty($oauthToken) && !empty($oauthVerifier)) {
            $temporaryCredentials = $this->request->session()->read('temporary_credentials');
            $tokenCredentials = $server->getTokenCredentials($temporaryCredentials, $oauthToken, $oauthVerifier);
            $user = (array)$server->getUserDetails($tokenCredentials);
            $user['token'] = [
                'accessToken' => $tokenCredentials->getIdentifier(),
                'tokenSecret' => $tokenCredentials->getSecret(),
            ];
            $this->request->session()->write(Configure::read('Users.Key.Session.social'), $user);
            try {
                $user = $this->Auth->identify();
                $this->_registry->getController()->_afterIdentifyUser($user, true);
            } catch (UserNotActiveException $ex) {
                $exception = $ex;
            } catch (AccountNotActiveException $ex) {
                $exception = $ex;
            } catch (MissingEmailException $ex) {
                $exception = $ex;
            }

            if (!empty($exception)) {
                return $this->failedSocialLogin($exception, $this->request->session()->read(Configure::read('Users.Key.Session.social')), true);
            }
        } else {
            $temporaryCredentials = $server->getTemporaryCredentials();
            $this->request->session()->write('temporary_credentials', $temporaryCredentials);
            $url = $server->getAuthorizationUrl($temporaryCredentials);

            return $this->_registry->getController()->redirect($url);
        }
    }

    /**
     * @param mixed $exception exception
     * @param mixed $data data
     * @param bool|false $flash flash
     * @return mixed
     */
    public function failedSocialLogin($exception, $data, $flash = false)
    {
        $msg = __d('CakeDC/Users', 'Issues trying to log in with your social account');

        if (isset($exception)) {
            if ($exception instanceof MissingEmailException) {
                if ($flash) {
                    $this->_registry->getController()->Flash->success(__d('CakeDC/Users', 'Please enter your email'));
                }
                $this->request->session()->write(Configure::read('Users.Key.Session.social'), $data);

                return $this->_registry->getController()->redirect(['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'socialEmail']);
            }
            if ($exception instanceof UserNotActiveException) {
                $msg = __d('CakeDC/Users', 'Your user has not been validated yet. Please check your inbox for instructions');
            } elseif ($exception instanceof AccountNotActiveException) {
                $msg = __d('CakeDC/Users', 'Your social account has not been validated yet. Please check your inbox for instructions');
            }
        }
        if ($flash) {
            $this->Auth->config('authError', $msg);
            $this->Auth->config('flash.params', ['class' => 'success']);
            $this->request->session()->delete(Configure::read('Users.Key.Session.social'));
            $this->_registry->getController()->Flash->success(__d('CakeDC/Users', $msg));
        }

        return $this->_registry->getController()->redirect(['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'login']);
    }

    /**
     * @param Event $event event
     */
    public function failedSocialLoginListener(Event $event)
    {
        return $this->failedSocialLogin($event->data['exception'], $event->data['rawData'], true);
    }

    /**
     * Social login
     *
     * @throws NotFoundException
     * @return array
     */
    public function socialLogin()
    {
        $socialProvider = $this->request->param('provider');
        $socialUser = $this->request->session()->read(Configure::read('Users.Key.Session.social'));

        if (empty($socialProvider) && empty($socialUser)) {
            throw new NotFoundException();
        }
        $user = $this->Auth->user();

        return $this->_afterIdentifyUser($user, true);
    }

    /**
     * Update remember me and determine redirect url after user identified
     * @param array $user user data after identified
     * @param bool $socialLogin is social login
     * @return array
     */
    protected function _afterIdentifyUser($user, $socialLogin = false, $googleAuthenticatorLogin = false)
    {
        if (!empty($user)) {
            $this->Auth->setUser($user);

            if ($googleAuthenticatorLogin) {
                $url = Configure::read('GoogleAuthenticator.verifyAction');

                return $this->_registry->getController()->redirect($url);
            }

            $event = $this->_registry->getController()->dispatchEvent(UsersAuthComponent::EVENT_AFTER_LOGIN, ['user' => $user]);
            if (is_array($event->result)) {
                return $this->_registry->getController()->redirect($event->result);
            }

            $url = $this->Auth->redirectUrl();

            return $this->_registry->getController()->redirect($url);
        } else {
            if (!$socialLogin) {
                $message = __d('CakeDC/Users', 'Username or password is incorrect');
                $this->Flash->error($message, 'default', [], 'auth');
            }

            return $this->_registry->getController()->redirect(Configure::read('Auth.loginAction'));
        }
    }

    /**
     * Login user
     *
     * @return mixed
     */
    public function login()
    {
        $event = $this->_registry->getController()->dispatchEvent(UsersAuthComponent::EVENT_BEFORE_LOGIN);
        if (is_array($event->result)) {
            return $this->_afterIdentifyUser($event->result);
        }
        if ($event->isStopped()) {
            return $this->_registry->getController()->redirect($event->result);
        }

        $socialLogin = $this->_isSocialLogin();
        $googleAuthenticatorLogin = $this->_isGoogleAuthenticator();

        if ($this->request->is('post')) {
            if (!$this->_checkReCaptcha()) {
                $this->_registry->getController()->Flash->error(__d('CakeDC/Users', 'Invalid reCaptcha'));

                return;
            }
            $user = $this->Auth->identify();

            return $this->_afterIdentifyUser($user, $socialLogin, $googleAuthenticatorLogin);
        }

        if (!$this->request->is('post') && !$socialLogin) {
            if ($this->Auth->user()) {
                $msg = __d('CakeDC/Users', 'You are already logged in');
                $this->_registry->getController()->Flash->error($msg);
                $url = $this->Auth->redirectUrl();

                return $this->_registry->getController()->redirect($url);
            }
        }
    }

    /**
     * Check if we are doing a social login
     *
     * @return bool true if social login is enabled and we are processing the social login
     * data in the request
     */
    protected function _isSocialLogin()
    {
        return Configure::read('Users.Social.login') &&
            $this->request->session()->check(Configure::read('Users.Key.Session.social'));
    }

    /**
     * Check if we doing Google Authenticator Two Factor auth
     * @return bool true if Google Authenticator is enabled
     */
    protected function _isGoogleAuthenticator()
    {
        return Configure::read('Users.GoogleAuthenticator.login');
    }

    /**
     * Check reCaptcha if enabled for login
     *
     * @return bool
     */
    protected function _checkReCaptcha()
    {
        if (!Configure::read('Users.reCaptcha.login')) {
            return true;
        }

        return $this->validateReCaptcha(
            $this->request->data('g-recaptcha-response'),
            $this->request->clientIp()
        );
    }

    /**
     * Verify for Google Authenticator
     * If Google Authenticator's enabled we need to verify
     * authenticated user. To avoid accidental access to
     * other URL's we store auth'ed used into temporary session
     * to perform code verification.
     *
     * @return void
     */
    public function verify()
    {
        if (!Configure::read('Users.GoogleAuthenticator.login')) {
            $message = __d('CakeDC/Users', 'Please enable Google Authenticator first.');
            $this->_registry->getController()->Flash->error($message, 'default', [], 'auth');

            $this->_registry->getController()->redirect(Configure::read('Auth.loginAction'));
        }

        // storing user's session in the temporary one
        // until the GA verification is checked
        $temporarySession = $this->Auth->user();
        $this->request->session()->delete('Auth.User');

        if (!empty($temporarySession)) {
            $this->request->session()->write('temporarySession', $temporarySession);
        }

        if (array_key_exists('secret', $temporarySession)) {
            $secret = $temporarySession['secret'];
        }

        $secretVerified = $temporarySession['secret_verified'];

        // showing QR-code until shared secret is verified
        if (!$secretVerified) {
            if (empty($secret)) {
                $secret = $this->_registry->getController()->GoogleAuthenticator->createSecret();

                // catching sql exception in case of any sql inconsistencies
                try {
                    $query = $this->getUsersTable()->query();
                    $query->update()
                        ->set(['secret' => $secret])
                        ->where(['id' => $temporarySession['id']]);
                    $executed = $query->execute();
                } catch (\Exception $e) {
                    $this->request->session()->destroy();
                    $message = __d('CakeDC/Users', $e->getMessage());
                    $this->_registry->getController()->Flash->error($message, 'default', [], 'auth');

                    return $this->_registry->getController()->redirect(Configure::read('Auth.loginAction'));
                }
            }

            $this->_registry->getController()->set('secretDataUri', $this->_registry->getController()->GoogleAuthenticator->getQRCodeImageAsDataUri($temporarySession['email'], $secret));
        }

        if ($this->request->is('post')) {
            $codeVerified = false;
            $verificationCode = $this->request->data('code');
            $user = $this->request->session()->read('temporarySession');
            $entity = $this->getUsersTable()->get($user['id']);

            if (!empty($entity['secret'])) {
                $codeVerified = $this->_registry->getController()->GoogleAuthenticator->verifyCode($entity['secret'], $verificationCode);
            }

            if ($codeVerified) {
                unset($user['secret']);

                if (!$user['secret_verified']) {
                    $this->getUsersTable()->query()->update()
                        ->set(['secret_verified' => true])
                        ->where(['id' => $user['id']])
                        ->execute();
                }

                $this->request->session()->delete('temporarySession');
                $this->request->session()->write('Auth.User', $user);
                $url = $this->Auth->redirectUrl();

                return $this->_registry->getController()->redirect($url);
            } else {
                $this->request->session()->destroy();
                $message = __d('CakeDC/Users', 'Verification code is invalid. Try again');
                $this->_registry->getController()->Flash->error($message, 'default', [], 'auth');

                return $this->_registry->getController()->redirect(Configure::read('Auth.loginAction'));
            }
        }
    }

    /**
     * Logout
     *
     * @return type
     */
    public function logout()
    {
        $eventBefore = $this->_registry->getController()->dispatchEvent(UsersAuthComponent::EVENT_BEFORE_LOGOUT);
        if (is_array($eventBefore->result)) {
            return $this->_registry->getController()->redirect($eventBefore->result);
        }

        $this->request->session()->destroy();
        $this->_registry->getController()->Flash->success(__d('CakeDC/Users', 'You\'ve successfully logged out'));

        $eventAfter = $this->_registry->getController()->dispatchEvent(UsersAuthComponent::EVENT_AFTER_LOGOUT);
        if (is_array($eventAfter->result)) {
            return $this->_registry->getController()->redirect($eventAfter->result);
        }

        return $this->_registry->getController()->redirect($this->Auth->logout());
    }

}
