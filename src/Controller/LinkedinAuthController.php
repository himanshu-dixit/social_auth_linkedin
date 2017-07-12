<?php

namespace Drupal\social_auth_linkedin\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_linkedin\LinkedinAuthManager;

use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\social_auth_linkedin\LinkedinAuthPersistentDataHandler;
use Symfony\Component\HttpFoundation\RequestStack;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Returns responses for Simple FB Connect module routes.
 */
class LinkedinAuthController extends ControllerBase {

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The Facebook authentication manager.
   *
   * @var \Drupal\social_auth_facebook\FacebookAuthManager
   */
  private $linkedinManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Facebook Persistent Data Handler.
   *
   * @var \Drupal\social_auth_facebook\FacebookAuthPersistentDataHandler
   */
  private $persistentDataHandler;

  /**
   * The data point to be collected.
   *
   * @var string
   */
  private $dataPoints;

  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * LinkedinAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_facebook network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_facebook\FacebookAuthManager $facebook_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth_facebook\FacebookAuthPersistentDataHandler $persistent_data_handler
   *   FacebookAuthPersistentDataHandler object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   Used for logging errors.
   */
  public function __construct(NetworkManager $network_manager, SocialAuthUserManager $user_manager, LinkedinAuthManager $linkedin_manager, RequestStack $request, LinkedinAuthPersistentDataHandler $persistent_data_handler, LoggerChannelFactoryInterface $logger_factory) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->linkedinManager = $linkedin_manager;
    $this->request = $request;
    $this->persistentDataHandler = $persistent_data_handler;
    $this->loggerFactory = $logger_factory;

    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_linkedin');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify([
      $this->persistentDataHandler->getSessionPrefix() . 'access_token',
    ]);
    $this->setting = $this->config('social_auth_linkedin.settings');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_linkedin.manager'),
      $container->get('request_stack'),
      $container->get('social_auth_linkedin.persistent_data_handler'),
      $container->get('logger.factory')
    );
  }

  /**
   * Response for path 'user/simple-linkedin-connect'.
   *
   * Redirects the user to Linkedin for authentication.
   */
  public function redirectToLinkedin() {
    /* @var \League\OAuth2\Client\Provider\Linkedin false $linkedin */
    $linkedin = $this->networkManager->createInstance('social_auth_linkedin')->getSdk();

    // If linkedin client could not be obtained.
    if (!$linkedin) {
      drupal_set_message($this->t('Social Auth Linkedin not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Linkedin service was returned, inject it to $linkedinManager.
    $this->linkedinManager->setClient($linkedin);

    // Generates the URL where the user will be redirected for Linkedin login.
    // If the user did not have email permission granted on previous attempt,
    // we use the re-request URL requesting only the email address.
    $linkedin_login_url = $this->linkedinManager->getLinkedinLoginUrl();

    $state = $this->linkedinManager->getState();

    $this->persistentDataHandler->set('oAuth2State', $state);

    return new TrustedRedirectResponse($linkedin_login_url);
  }

  /**
   * Response for path 'user/login/linkedin/callback'.
   *
   * Linkedin returns the user here after user has authenticated in Linkedin.
   */
  public function returnFromLinkedin() {
    // Checks if user cancel login via Linkedin.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \League\OAuth2\Client\Provider\Linkedin false $linkedin */
    $linkedin = $this->networkManager->createInstance('social_auth_linkedin')->getSdk();

    // If Linkedin client could not be obtained.
    if (!$linkedin) {
      drupal_set_message($this->t('Social Auth Linkedin not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->persistentDataHandler->get('oAuth2State');

    if (!empty($_GET['error'])) {
      drupal_set_message($this->t('Linkedin login failed. Probably User Declined Authentication.'), 'error');
      return $this->redirect('user.login');
    }
    else if (empty($_GET['state']) || ($_GET['state'] !== $state)) {
      unset($_SESSION['oauth2state']);
      drupal_set_message($this->t('Linkedin login failed. Unvalid oAuth2 State.'), 'error');
      return $this->redirect('user.login');
    }


    $this->linkedinManager->setClient($linkedin)->authenticate();

    // Gets user's FB profile from Linkedin API.
    if (!$linkedin_profile = $this->linkedinManager->getUserInfo()) {
      drupal_set_message($this->t('Linkedin login failed, could not load Linkedin profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }


    $data = [];

    $data_points = explode(',', $this->getDataPoints());

    foreach ($data_points as $data_point) {
      switch ($data_point) {
        default: $this->loggerFactory->get($this->userManager->getPluginId())->error(
          'Failed to fetch Data Point. Invalid Data Point: @$data_point', ['@$data_point' => $data_point]);
      }
    }
    // Saves access token to session.
    $this->persistentDataHandler->set('access_token', $this->linkedinManager->getAccessToken());
    // If user information could be retrieved.
    // Check for the profile User
    return $this->userManager->authenticateUser($linkedin_profile->getFirstName() . ' ' . $linkedin_profile->getLastName(), $linkedin_profile->getEmail(), 'social_auth_linkedin', $linkedin_profile->getId(), $linkedin_profile->getImageurl(), json_encode($data));
  }

  /**
   * Gets the data Point defined the settings form page.
   *
   * @return string
   *   Data points separtated by comma.
   */
  public function getDataPoints() {
    if (!$this->dataPoints) {
      $this->dataPoints = $this->config('social_auth_linkedin.settings')->get('data_points');
    }
    return $this->dataPoints;
  }

}
