<?php
namespace Users\Test\App\View\Cell;

use Cake\View\Cell;

/**
 * Cell to test AuthLinks working inside cells
 */
class AuthCell extends Cell
{
    public $helpers = [
        'CakeDC/Users.AuthLink'
    ];

    public function display()
    {
    }
}
