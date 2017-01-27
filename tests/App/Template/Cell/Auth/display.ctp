hi, from the cell

This link should be rendered <?= $this->AuthLink('allowed', [
    'plugin' => 'CakeDC/Users',
    'controller' => 'Users',
    'action' => 'login',
]) ?>

This link should not be rendered <?= $this->AuthLink('not-allowed', [
    'plugin' => 'CakeDC/Users',
    'prefix' => 'admin',
    'controller' => 'Users',
    'action' => 'add',
]) ?>