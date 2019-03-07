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


class LoginFormAuthenticator extends AbstractFormLoginAuthenticator
{
    use TargetPathTrait;

    private $ldap;
    private $router;
    private $csrfTokenManager;

    protected $options;

    public function __construct(Ldap $ldap, RouterInterface $router, CsrfTokenManagerInterface $csrfTokenManager, array $options = [])
    {
        $this->ldap = $ldap;
        $this->router = $router;
        $this->csrfTokenManager = $csrfTokenManager;

        $resolver = new OptionsResolver();
        $this->configureOptions($resolver);
        $this->options = $resolver->resolve($options);
    }

    protected function configureOptions(OptionsResolver $resolver)
    {
        $resolver
            ->setDefault('login_route', 'login')
            ->setDefault('default_success_route', 'index')
            ->setDefault('login_field', 'login')
            ->setDefault('password_field', 'password')
            ->setDefault('csrf_token_field', '_csrf_token')
        ;    
    }

    public function supports(Request $request)
    {
        // return 'login' === $request->attributes->get('_route')
        return $this->options['login_route'] === $request->attributes->get('_route')
            && $request->isMethod('POST');
    }

    public function getCredentials(Request $request)
    {
        $credentials = [
            'login' => $request->request->get($this->options['login_field']),
            'password' => $request->request->get($this->options['password_field']),
            'csrf_token' => $request->request->get($this->options['csrf_token_field']),
        ];
        $request->getSession()->set(
            Security::LAST_USERNAME,
            $credentials['login']
        );

        return $credentials;
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $token = new CsrfToken('authenticate', $credentials['csrf_token']);
        if (!$this->csrfTokenManager->isTokenValid($token)) {
            throw new InvalidCsrfTokenException();
        }
      
        $user = $userProvider->loadUserByUsername($credentials['login']);
        
        if (!$user) {
            // fail authentication with a custom error
            throw new CustomUserMessageAuthenticationException('Invalid credentials.');
        }

        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        try {
             $this->ldap->bind($user->getDn(), $credentials['password']);   
        }
        catch (\Exception $e)
        {
            return false;
        }
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $providerKey)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->router->generate($this->options['default_success_route']));
    }

    protected function getLoginUrl()
    {
        return $this->router->generate($this->options['login_route']);
    }
}