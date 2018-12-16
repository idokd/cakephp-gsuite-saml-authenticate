<?php

namespace App\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Http\ServerRequest;
use Cake\Http\Response;
use App\Auth\Event;
use Cake\Controller\Exception\AuthSecurityException;

use SimpleSAML\Auth\Simple;
use SAML2\AuthnRequest;
use SAML2\HTTPRedirect;
use SAML2\HTTPPost;

//use SAML2\Utilities;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class SamlAuthenticate extends BaseAuthenticate {

    const QUERY_STRING_AUTHENTICATE = 'authenticate';

    private $issuer = null;
    private $destination = null;
    private $acs = null;
    private $idp = null;
    private $certificate = null;
    private $nameid = array('Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', 'AllowCreate' => true);
    private $here = null;

    public function initialize($request) {
        if (!$this->issuer) {
            $this->issuer = $this->getConfig('issuer');
            $this->destination = $this->getConfig('destination');
            $this->acs = $this->getConfig('acs');
            $this->idp = $this->getConfig('idp');
            $this->certificate = $this->getConfig('certificate');
            if ($this->getConfig('nameid')) $this->nameid = $this->getConfig('nameid');
            // TODO: implement for non-standard port - $request->port()
            $this->here = ($request->is('ssl') ? 'https://' : 'http://').$request->host().$request->getAttribute('here');
        }
    }

    public function authenticate(ServerRequest $request, Response $response) {
        $this->initialize($request);
        $saml = $request->getData('SAMLResponse');
        if (!$saml || $this->here != $this->acs) return(false);

        $binding = new HTTPPost();
        $saml = $binding->receive();
        if (!$saml->isSuccess()) return;

        if ($saml->getDestination() != $this->here)
            throw new AuthSecurityException(_('SAML: Destination/Recipient Mismatch'));
        if ($saml->getIssuer() != $this->idp)
            throw new AuthSecurityException(_('SAML: IdP Issuer Mismatch'));

        $session = $this->_registry->getController()->getRequest()->getSession();
        $session->read('Saml.id');

        if ($session->read('Saml.id') != $saml->getInResponseTo())
            throw new AuthSecurityException(_('SAML: Not corresponding response'));

        if (!$saml->getAssertions())
            throw new AuthSecurityException(_('SAML: Empty response, no assertion.'));

        $assertion = $saml->getAssertions()[0];

        if ($assertion->getValidAudiences() && !in_array($this->issuer, $assertion->getValidAudiences()))
            throw new AuthSecurityException(_('SAML: Not a valid service provider'));

        $now = time();
        if (
            ($assertion->getNotBefore() && $now < $assertion->getNotBefore())
            || ($assertion->getNotOnOrAfter() && $now > $assertion->getNotOnOrAfter())
            || ($assertion->getSessionNotOnOrAfter() && $now > $assertion->getSessionNotOnOrAfter())
          )
            throw new AuthSecurityException(_('SAML: None valid period'));

        // TODO: valid signature
        //if ($info['certificate'] != $this->certificate)
        //    throw new AuthSecurityException(_('SAML: Certificate Mismatch'));
        $user = array();
        $user['username'] = $assertion->getNameId()->value;
        $user['type'] = 'saml';
        $user['saml'] = array();
        $user['saml']['sessionid'] = $assertion->getSessionIndex();
        if ($assertion->getSessionNotOnOrAfter()) $user['saml']['session_expiry'] = $assertion->getSessionNotOnOrAfter();
        // TODO: set expiration date to session based on session_expiry
        return($user);
    }

    public function unauthenticated(ServerRequest $request, Response $response) {
        if (!$request->getQuery(static::QUERY_STRING_AUTHENTICATE)) return;
        $this->initialize($request);
        $saml = new AuthnRequest();
        $saml->setIssuer($this->issuer);
        $saml->setDestination($this->destination);
        $saml->setAssertionConsumerServiceURL($this->acs);
        $saml->setNameIdPolicy($this->nameid);
        $saml->getRelayState($this->here);
        $session = $this->_registry->getController()->getRequest()->getSession();
        $session->write('Saml.redirect', $this->here);
        $session->write('Saml.id', $saml->getId());

        // TODO: sign request
        //$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'public']);
        //$key->loadKey(CONFIG.'certs'.DS.'GoogleIDPCertificate-enlight.mx.pem', true, true);
        //$saml->setSignatureKey($key);

        $binding = new HTTPRedirect();
        $binding->send($saml);
    }

    public function afterIdentify(Event $event, array $user) {
        $this->_registry->getController()->getRequest()->getSession()->write('Auth.user', $user);
    }

    public function logout(Event $event, array $user) {
        $this->_registry->getController()->getRequest()->getSession()->destroy();
        // TODO: Notify SSO of the logout via LogoutRequest
    }

    public function implementedEvents() {
      return [
          'Auth.afterIdentify' => 'afterIdentify',
          'Auth.logout' => 'logout'
      ];
    }
}
