# cakephp-gsuite-saml
G Suite / Google Authentication via SAML Apps &amp; SimpleSAML PHP / SAML2

The following code will enable your CakePHP (v3+) to integrate a login via Google Suite / Google Apps
you should configure in admin.google.com your SAML APPS,

Setting the following; (check google help here: https://support.google.com/a/answer/6087519?hl=en)

> ACS URL: https://{domain-name}/saml
>
> Entity ID / Entity ID (Issuer / App): {google-app-entity-id}
>
> Start URL: https://{domain-name} 

Download your google certificate, and enable users to this SAML Apps so you can test it

# Login button ?authenticate=google
You login button or anyother way to login to the site you should append to the url you with to redirect
after the ?authenticate=google

so
```
<a href="/orders?authenticate=google">Go to Orders</a>
```
will take users to /orders but before will authenticate via google SAML app


# Add packages in composer
You will need the following two packages:
- simplesamlphp/saml2
- simplesamlphp/simplesamlphp

# Controllers/AppController to apply to all Conrollers
Create a AppController to add to all site 
```
class AppController extends Controller
{

    // init the Authentication with SAML and configuration
    public function initialize() {
        parent::initialize();
        $this->loadComponent('Auth', ['authenticate' => ['Saml']]);
        $this->Auth->setConfig('authenticate', 'Saml' => [
            'issuer' => '{google-app-entity-id}',
            'destination' => 'https://accounts.google.com/o/saml2/idp?idpid={google-code-id}',
            'idp' => 'https://accounts.google.com/o/saml2?idpid={google-code-id}',
            'acs' => 'https://{domain-name}/saml',
            'certfile' => 'GoogleIDPCertificate.pem',
            'certificate' => 'MIID..... <--- here is your google certificate content without the -----BEGIN CERTIFICATE...']);
    }

    // Deny access too all urls, unless authenticated 
    public function beforeFilter(Event $event) {
        parent::beforeFilter($event);
        $this->Auth->deny();
    }

}
```
# TBC: config/routes.php (: Does it a must?) - disable middleware

Disable middleware
```
// $routes->applyMiddleware('csrf');
```
Or leave it enabled and create new scope for /saml with out the csrf middleware set.
```
Router::scope('/saml', function (RouteBuilder $routes) {
    $routes->connect('/:action', ['controller' => 'Saml']);
    $routes->fallbacks(DashedRoute::class);
});
```
