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

namespace CakeDC\Users\Test\TestCase\Util;

use Cake\Event\Event;

trait MockTrait
{
    /**
     * mock utility
     *
     * @param Event $event event
     * @return void
     */
    protected function _mockDispatchEvent(Event $event = null, &$target = null)
    {
        if (is_null($event)) {
            $event = new Event('cool-name-here');
        }
        $target->expects($this->any())
            ->method('dispatchEvent')
            ->will($this->returnValue($event));
    }
}
