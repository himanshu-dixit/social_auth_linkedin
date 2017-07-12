<?php

namespace Drupal\social_auth_linkedin\Settings;

/**
 * Defines the settings interface.
 */
interface LinkedinAuthSettingsInterface {

  /**
   * Gets the application ID.
   *
   * @return mixed
   *   The application ID.
   */
  public function getClientId();

  /**
   * Gets the application secret.
   *
   * @return string
   *   The application secret.
   */
  public function getClientSecret();


}
