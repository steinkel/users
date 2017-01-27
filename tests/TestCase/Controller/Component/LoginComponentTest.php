<?php
/**
 * Copyright 2010 - 2015, Cake Development Corporation (+1 702 425 5085) (http://cakedc.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright 2010 - 2015, Cake Development Corporation (+1 702 425 5085) (http://cakedc.com)
 * @license MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

namespace CakeDC\Users\Test\TestCase\Controller\Traits;

use Cake\Controller\ComponentRegistry;
use Cake\Network\Session;
use CakeDC\Users\Controller\Component\LoginComponent;
use CakeDC\Users\Controller\Component\UsersAuthComponent;
use CakeDC\Users\Controller\Traits\LoginTrait;
use CakeDC\Users\Exception\AccountNotActiveException;
use CakeDC\Users\Exception\MissingEmailException;
use CakeDC\Users\Exception\UserNotActiveException;
use Cake\Controller\Controller;
use Cake\Core\Configure;
use Cake\Event\Event;
use Cake\Network\Request;
use Cake\ORM\Entity;
use Cake\TestSuite\TestCase;
use CakeDC\Users\Test\TestCase\Util\MockTrait;

class LoginComponentTest extends TestCase
{
    use MockTrait;

    /**
     * setup
     *
     * @return void
     */
    public function setUp()
    {
        $this->Controller = new Controller(new Request(['session' => new Session()]));
        $this->ComponentRegistry = new ComponentRegistry($this->Controller);
        $this->Login = new LoginComponent($this->ComponentRegistry);
        $this->Session = new Session();
    }

    /**
     * tearDown
     *
     * @return void
     */
    public function tearDown()
    {
        parent::tearDown();
        $this->Session->destroy();
    }

    /**
     * test
     *
     * @return void
     */
    public function testLoginHappy()
    {
        $this->Controller = $this->getMockBuilder('Cake\Controller\Controller')
            ->setMethods(['redirect'])
            ->disableOriginalConstructor()
            ->getMock();
        $this->ComponentRegistry = new ComponentRegistry($this->Controller);
        $this->Login = new LoginComponent($this->ComponentRegistry);

        $redirectLoginOK = '/';

        $this->Login->request = $this->getMockBuilder('Cake\Network\Request')
            ->setMethods(['is'])
            ->getMock();
        $this->Login->request->expects($this->any())
            ->method('is')
            ->with('post')
            ->will($this->returnValue(true));

        $this->Login->Auth = $this->getMockBuilder('Cake\Controller\Component\AuthComponent')
            ->setMethods(['user', 'identify', 'setUser', 'redirectUrl'])
            ->disableOriginalConstructor()
            ->getMock();
        $user = [
            'id' => 1,
        ];
        $this->Login->Auth->expects($this->at(0))
            ->method('identify')
            ->will($this->returnValue($user));
        $this->Login->Auth->expects($this->at(1))
            ->method('setUser')
            ->with($user);
        $this->Login->Auth->expects($this->at(2))
            ->method('redirectUrl')
            ->will($this->returnValue($redirectLoginOK));
        $this->Controller->expects($this->once())
            ->method('redirect')
            ->with($redirectLoginOK);
        $this->Login->login();
    }

    /**
     * test
     *
     * @return void
     */
    public function testAfterIdentifyEmptyUser()
    {
        $this->_mockDispatchEvent(new Event('event'));
        $this->Login->request = $this->getMockBuilder('Cake\Network\Request')
            ->setMethods(['is'])
            ->getMock();
        $this->Login->request->expects($this->any())
            ->method('is')
            ->with('post')
            ->will($this->returnValue(true));
        $this->Login->Auth = $this->getMockBuilder('Cake\Controller\Component\AuthComponent')
            ->setMethods(['user', 'identify', 'setUser', 'redirectUrl'])
            ->disableOriginalConstructor()
            ->getMock();
        $user = [];
        $this->Login->Auth->expects($this->once())
            ->method('identify')
            ->will($this->returnValue($user));
        $this->Login->Flash = $this->getMockBuilder('Cake\Controller\Component\FlashComponent')
            ->setMethods(['error'])
            ->disableOriginalConstructor()
            ->getMock();
        $this->Login->Flash->expects($this->once())
            ->method('error')
            ->with('Username or password is incorrect', 'default', [], 'auth');
        $this->Login->login();
    }

    /**
     * test
     *
     * @return void
     */
    public function testAfterIdentifyEmptyUserSocialLogin()
    {
        $this->Login = $this->getMockBuilder('CakeDC\Users\Controller\Traits\LoginTrait')
            ->setMethods(['dispatchEvent', 'redirect', '_isSocialLogin'])
            ->getMockForTrait();
        $this->Login->expects($this->any())
            ->method('_isSocialLogin')
            ->will($this->returnValue(true));
        $this->_mockDispatchEvent(new Event('event'));
        $this->Login->request = $this->getMockBuilder('Cake\Network\Request')
            ->setMethods(['is'])
            ->getMock();
        $this->Login->Auth = $this->getMockBuilder('Cake\Controller\Component\AuthComponent')
            ->setMethods(['user', 'identify', 'setUser', 'redirectUrl'])
            ->disableOriginalConstructor()
            ->getMock();

        $this->Login->login();
    }

    /**
     * test
     *
     * @return void
     */
    public function testLoginBeforeLoginReturningArray()
    {
        $user = [
            'id' => 1
        ];
        $event = new Event('event');
        $event->result = $user;
        $this->Login->expects($this->at(0))
            ->method('dispatchEvent')
            ->with(UsersAuthComponent::EVENT_BEFORE_LOGIN)
            ->will($this->returnValue($event));
        $this->Login->expects($this->at(1))
            ->method('dispatchEvent')
            ->with(UsersAuthComponent::EVENT_AFTER_LOGIN)
            ->will($this->returnValue(new Event('name')));
        $this->Login->Auth = $this->getMockBuilder('Cake\Controller\Component\AuthComponent')
            ->setMethods(['setUser', 'redirectUrl'])
            ->disableOriginalConstructor()
            ->getMock();
        $redirectLoginOK = '/';
        $this->Login->Auth->expects($this->once())
            ->method('setUser')
            ->with($user);
        $this->Login->Auth->expects($this->once())
            ->method('redirectUrl')
            ->will($this->returnValue($redirectLoginOK));
        $this->Login->expects($this->once())
            ->method('redirect')
            ->with($redirectLoginOK);
        $this->Login->login();
    }

    /**
     * test
     *
     * @return void
     */
    public function testLoginBeforeLoginReturningStoppedEvent()
    {
        $event = new Event('event');
        $event->result = '/';
        $event->stopPropagation();
        $this->Login->expects($this->at(0))
            ->method('dispatchEvent')
            ->with(UsersAuthComponent::EVENT_BEFORE_LOGIN)
            ->will($this->returnValue($event));
        $this->Login->expects($this->once())
            ->method('redirect')
            ->with('/');
        $this->Login->login();
    }

    /**
     * test
     *
     * @return void
     */
    public function testLoginGet()
    {
        //$this->_mockDispatchEvent(new Event('event'), $this->Login);
        $socialLogin = Configure::read('Users.Social.login');
        Configure::write('Users.Social.login', false);
        $this->Controller->Auth = $this->getMockBuilder('Cake\Controller\Component\AuthComponent')
            ->setMethods(['user'])
            ->disableOriginalConstructor()
            ->getMock();
        $this->Login->request = $this->getMockBuilder('Cake\Network\Request')
            ->setMethods(['is'])
            ->disableOriginalConstructor()
            ->getMock();
        $this->Login->request->expects($this->at(0))
            ->method('is')
            ->with('post')
            ->will($this->returnValue(false));
        $this->Login->request->expects($this->at(1))
            ->method('is')
            ->with('post')
            ->will($this->returnValue(false));
        $this->Login->login();
    }

    /**
     * test
     *
     * @return void
     */
    public function testLogout()
    {
        $this->_mockDispatchEvent(new Event('event'));
        $this->Login->Auth = $this->getMockBuilder('Cake\Controller\Component\AuthComponent')
            ->setMethods(['logout'])
            ->disableOriginalConstructor()
            ->getMock();
        $redirectLogoutOK = '/';
        $this->Login->Auth->expects($this->once())
            ->method('logout')
            ->will($this->returnValue($redirectLogoutOK));
        $this->Login->expects($this->once())
            ->method('redirect')
            ->with($redirectLogoutOK);
        $this->Login->Flash = $this->getMockBuilder('Cake\Controller\Component\FlashComponent')
            ->setMethods(['success'])
            ->disableOriginalConstructor()
            ->getMock();
        $this->Login->Flash->expects($this->once())
            ->method('success')
            ->with('You\'ve successfully logged out');
        $this->Login->logout();
    }

    /**
     * test
     *
     * @return void
     */
    public function testFailedSocialLoginMissingEmail()
    {
        $event = new Entity();
        $event->data = [
            'exception' => new MissingEmailException('Email not present'),
            'rawData' => [
                'id' => 11111,
                'username' => 'user-1'
            ]
        ];
        $this->_mockFlash();
        $this->_mockRequestGet();
        $this->Login->Flash->expects($this->once())
            ->method('success')
            ->with('Please enter your email');

        $this->Login->expects($this->once())
            ->method('redirect')
            ->with(['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'socialEmail']);

        $this->Login->failedSocialLogin($event->data['exception'], $event->data['rawData'], true);
    }

    /**
     * test
     *
     * @return void
     */
    public function testFailedSocialUserNotActive()
    {
        $event = new Entity();
        $event->data = [
            'exception' => new UserNotActiveException('Facebook user-1'),
            'rawData' => [
                'id' => 111111,
                'username' => 'user-1'
            ]
        ];
        $this->_mockFlash();
        $this->_mockRequestGet();
        $this->Login->Flash->expects($this->once())
            ->method('success')
            ->with('Your user has not been validated yet. Please check your inbox for instructions');

        $this->Login->expects($this->once())
            ->method('redirect')
            ->with(['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'login']);

        $this->Login->Auth->expects($this->at(0))
            ->method('config')
            ->with('authError', 'Your user has not been validated yet. Please check your inbox for instructions');

        $this->Login->Auth->expects($this->at(1))
            ->method('config')
            ->with('flash.params', ['class' => 'success']);

        $this->Login->failedSocialLogin($event->data['exception'], $event->data['rawData'], true);
    }

    /**
     * test
     *
     * @return void
     */
    public function testFailedSocialUserAccountNotActive()
    {
        $event = new Entity();
        $event->data = [
            'exception' => new AccountNotActiveException('Facebook user-1'),
            'rawData' => [
                'id' => 111111,
                'username' => 'user-1'
            ]
        ];
        $this->_mockFlash();
        $this->_mockRequestGet();
        $this->Login->Flash->expects($this->once())
            ->method('success')
            ->with('Your social account has not been validated yet. Please check your inbox for instructions');

        $this->Login->expects($this->once())
            ->method('redirect')
            ->with(['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'login']);

        $this->Login->failedSocialLogin($event->data['exception'], $event->data['rawData'], true);
    }


    /**
     * test
     *
     * @return void
     */
    public function testFailedSocialUserAccount()
    {
        $event = new Entity();
        $event->data = [
            'rawData' => [
                'id' => 111111,
                'username' => 'user-1'
            ]
        ];
        $this->_mockFlash();
        $this->_mockRequestGet();
        $this->Login->Flash->expects($this->once())
            ->method('success')
            ->with('Issues trying to log in with your social account');

        $this->Login->expects($this->once())
            ->method('redirect')
            ->with(['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'login']);

        $this->Login->failedSocialLogin(null, $event->data['rawData'], true);
    }
}
