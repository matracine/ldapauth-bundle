<?php
namespace mracine\LdapAuthBundle;

use Symfony\Component\Security\Core\User\LdapUserProvider as SymfonyLdapUserProvider;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;

use mracine\LdapAuthBundle\LdapUser;

/**
 * Represents a user extracted from Ldap server
 *
 * @author Matthieu Racine <matthieu.racine@gmail.com>
 */
class LdapUserProvider extends SymfonyLdapUserProvider
{

    // public function loadUserByUsername($username)
    // {
    //     dump($username); exit();
    //     parent::loadUserByUsername($username);
    // }

    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof LdapUser) {
           throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }
        return new LdapUser($user->getUsername(), null, $user->getLdapEntry(), $user->getRoles());
    }
    /**
    * {@inheritdoc}
    */
    public function supportsClass($class)
    {
        return $class === LdapUser::class;
    }
    /**
    * {@inheritdoc}
    */
    protected function loadUser($username, Entry $entry)
    {
                // dump($this->getAttributeValue($entry, 'dn'));exit();

        $user = parent::loadUser($username, $entry);
        $ldapUser = new LdapUser($username, $user->getPassword(), $entry, $user->getRoles());                

        return new LdapUser($username, $user->getPassword(), $entry, $user->getRoles());
    }

}