<?php
namespace mracine\LdapAuthBundle;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Represents a user extracted from Ldap server
 *
 * @author Matthieu Racine <matthieu.racine@gmail.com>
 */

class LdapUser implements UserInterface, EquatableInterface
{
    /**
     * @var string short user name
     */ 
    private $username;

    /**
     * @var string clear texte user password
     */
    private $password;

    /**
     * @var string[] user's roles list
     */
    private $roles;

    /**
     * @var Entry the ldap user's entry (record) received from the Ldap server after authentication
     */
    protected $ldapEntry;

    /**
     * Contrutctor
     *
     * @param string $username the user's username
     * @param string $password the user's password
     * @param Entry $entry the user's associated ldap entry (contains user's DN)
     * @param string[] $roles the user roles
     */
    public function __construct(
        ?string $username, 
        ?string $password, 
        Entry $ldapEntry, 
        array $roles = []
    )
    {
        if ('' === $username || null === $username) {
            throw new \InvalidArgumentException('The username cannot be empty.');
        }

        $this->username = $username;
        $this->password = $password;
        $this->roles = $roles;
        $this->ldapEntry = $ldapEntry;
    }

    /**
     * Convert LdapUser to human readable string value
     *
     * @return string the user name
     */ 

    public function __toString()
    {
        return $this->getUsername();
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
    }

    /**
     * retreive the ldap entry of the user
     * 
     * @return Entry the Ldap entry
     */
    public function getLdapEntry()
    {
        return $this->ldapEntry;   
    }
    
    /**
     * retreive the Ldap Distinguished Name (DN) of the user
     *
     * DN is a unique key for the Ldap server that identifies the user entry
     * DN has the form : "uid=username,ou=myservice,dc=myorganisation,dc=fr"
     *
     * @return string the DN
     */   
    public function getDn()
    {
        return $this->ldapEntry->getDn();
    }

    /**
     * {@inheritdoc}
     */
    public function isEqualTo(UserInterface $user)
    {
        if (!$user instanceof self) {
            return false;
        }

        if ($this->getPassword() !== $user->getPassword()) {
            return false;
        }

        if ($this->getSalt() !== $user->getSalt()) {
            return false;
        }

        if ($this->getUsername() !== $user->getUsername()) {
            return false;
        }

        return true;
    }

    /**
     * Extracts single value from entry's array value by key.
     *
     * @param Entry       $entry        Ldap entry
     * @param string      $key          Key
     * @param null|string $defaultValue Default value
     *
     * @return string|null
     */
    protected function extractSingleValueByKeyFromEntry(Entry $entry, $key, $defaultValue = null)
    {
        $value = $this->extractFromLdapEntry($entry, $key, $defaultValue);
        return is_array($value) && isset($value[0]) ? $value[0] : $defaultValue;
    }
    /**
     * Extracts value from entry by key.
     *
     * @param Entry  $entry        Ldap entry
     * @param string $key          Key
     * @param mixed  $defaultValue Default value
     *
     * @return array|mixed
     */
    protected function extractFromLdapEntry(Entry $entry, $key, $defaultValue = null)
    {
        if (!$entry->hasAttribute($key)) {
            return $defaultValue;
        }
        return $entry->getAttribute($key);
    }    
}
