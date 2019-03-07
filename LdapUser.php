<?php
namespace mracine\LdapAuthBundle;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Ldap\Entry;


class LdapUser implements UserInterface, EquatableInterface
{
    private $username;
    private $password;
    private $roles;

    protected $ldapEntry;

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

    public function getLdapEntry()
    {
        return $this->ldapEntry;   
    }
    
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
