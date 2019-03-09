<?php
namespace mracine\LdapAuthBundle;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Guard\Authenticator\AbstractFormLoginAuthenticator;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\OptionsResolver\OptionsResolver;


/**
 * Guard class to use ldap authentication via login form
 *
 * @author Matthieu Racine <matthieu.racine@gmail.com>
 */
class LoginFormAuthenticator extends AbstractFormLoginAuthenticator
{
    use TargetPathTrait;

    /**
     * @var Ldap used to comunicate with Ldap server
     */
    private $ldap;

    /**
     * @var RouterInterface for the application route generation
     */ 
    private $router;

    /**
     * @var CsrfTokenManagerInterface for CSRF management
     */
    private $csrfTokenManager;

    /**
     * @var array Array of options
     * @see configureOptions method
     */
    protected $options;

    /**
     * Construct the guard object
     *
     * @var Ldap $ldap used to comunicate with Ldap server
     * @var RouterInterface $router the Symfony router to use for redirect routes generation
     * @var CsrfTokenManagerInterface|null $csrfTokenManager used to manage CSRF in login form. Null value wil not use CSRF (bad !!!)
     * @var array $options Froms options (login, password, csrf Forms felds names, redirect route on successfull authentocation)
     */
    public function __construct(Ldap $ldap, RouterInterface $router, CsrfTokenManagerInterface $csrfTokenManager=null, array $options = [])
    {
        $this->ldap = $ldap;
        $this->router = $router;
        $this->csrfTokenManager = $csrfTokenManager;

        $resolver = new OptionsResolver();
        $this->configureOptions($resolver);
        $this->options = $resolver->resolve($options);
    }

    /**
     * Validates and sets defaults values of options passed to the constructor
     *
     * Valids options are :
     *  - loging_route : the route used to validate the form
     *  - login_field : the form's field name containing the user's login 
     *  - password_field : the form's field name containing the user's password 
     *  - csrf_token_field : the form's field name containing the CSRF token
     *  - default_success_route : the name of the route to redirect the user on success authentication if user acces directly the login form (was not redirected to by firewall) 
     *
     * @param OptionsResolver $resolver th option resolver object used
     * @throws Symfony\Component\OptionsResolver\Exception\ExceptionInterface on validation error
     * @return null
     */

    protected function configureOptions(OptionsResolver $resolver)
    {
        $resolver
            ->setDefault('login_route', 'login')
            ->setDefault('login_field', 'login')
            ->setDefault('password_field', 'password')
            ->setDefault('csrf_token_field', '_csrf_token')
            ->setDefault('default_success_route', 'index')
        ;    
    }

    /**
     * {@inheritdoc}
     * Only activate the authentication process if we post to the login route
     */
    public function supports(Request $request)
    {
        return $this->options['login_route'] === $request->attributes->get('_route')
            && $request->isMethod('POST');
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        $credentials = [
            'login' => $request->request->get($this->options['login_field']),
            'password' => $request->request->get($this->options['password_field']),
        ];
        // Only use the csrf token if we have a CSRF manager 
        if (!is_null($this->csrfTokenManager))
        {
            $credentials['csrf_token'] = $request->request->get($this->options['csrf_token_field']);
        }

        $request->getSession()->set(
            Security::LAST_USERNAME,
            $credentials['login']
        );

        return $credentials;
    }

    /**
     * {@inheritdoc}
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        // If form use a CSRF Token
        if (!is_null($this->csrfTokenManager))
        {
            $token = new CsrfToken('authenticate', $credentials['csrf_token']);
            if (!$this->csrfTokenManager->isTokenValid($token))
            {
                throw new InvalidCsrfTokenException();
            }
        }
      
        $user = $userProvider->loadUserByUsername($credentials['login']);
        
        if (!$user) {
            // fail authentication with a custom error
            throw new CustomUserMessageAuthenticationException('Invalid credentials.');
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        /*
         * Ldap authentication process : 
         *  - retreive the user's DN by searching the ldap directory for the user
         *  - try to connect to Ldap server with the user's DN and the provided password
         *  On connection success, the password is valid.
         */
        try {
             $this->ldap->bind($user->getDn(), $credentials['password']);   
        }
        catch (\Exception $e)
        {
            return false;
        }
        return true;
    }

    /**
     * {@inheritdoc}
     * 
     * 
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // user was redirected by the firewall ?
        if ($targetPath = $this->getTargetPath($request->getSession(), $providerKey)) {
            return new RedirectResponse($targetPath);
        }

        // user was nt redirected by the firewall, go to default location
        return new RedirectResponse($this->router->generate($this->options['default_success_route']));
    }

    /**
     * {@inheritdoc}
     */
    protected function getLoginUrl()
    {
        return $this->router->generate($this->options['login_route']);
    }
}