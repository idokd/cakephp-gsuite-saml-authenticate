<?php

namespace App\Controller;

use Cake\Event\Event;

class SamlController extends AppController {

    public function beforeFilter(Event $event) {
        parent::beforeFilter($event);
        $this->Auth->deny();
        $this->Auth->allow(['index']);
        return(null);
    }

    public function index() {
        $redirect = null;
        if ($user = $this->Auth->identify()) {
            $this->Auth->setUser($user);
            $redirect = $this->getRequest()->getSession()->read('Saml.redirect');
        }
        return($this->redirect($this->Auth->redirectUrl($redirect)));
    }

    public function logout() {
        return($this->redirect($this->Auth->logout()));
    }

    public function view() {
        print_r($this->Auth->user());
        print_r($_SESSION);
        die();
    }

}
