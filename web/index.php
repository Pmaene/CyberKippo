<?php
/**
 * CyberKippo is an interface for the Kippo SSH honeypot which
 * interfaces with the Collective Intelligence Framework
 * for threat intelligence, built by @pmaene.
 *
 * @author Pieter Maene <p.maene@gmail.com>
 */

require_once __DIR__ . '/../vendor/autoload.php';

// Bootstrap
$app = new Silex\Application();
$app['debug'] = true;

// Registering Service Providers
$app->register(new Silex\Provider\DoctrineServiceProvider(), array(
    'db.options' => array(
        'driver'    => 'pdo_mysql',
        'host'      => 'localhost',
        'dbname'    => 'cyber_kippo',
        'user'      => 'cyber_kippo',
        'password'  => '9hFDxWHSEWfmyLyK',
    ),
));

$app->register(new Silex\Provider\TwigServiceProvider(), array(
    'twig.path' => __DIR__ . '/../resources/views/',
));
$app->register(new Silex\Provider\UrlGeneratorServiceProvider());

$app->register(new SilexAssetic\AsseticServiceProvider(), array(
    'assetic.path_to_web' => __DIR__,
    'assetic.options' => array(
        'auto_dump_assets' => true,
        'debug'            => $app['debug']
    ),
));

// Assetic Configuration
if ($app['assetic.options']['auto_dump_assets']) {
    $dumper = $app['assetic.dumper'];
    if (isset($app['twig']))
        $dumper->addTwigAssets();
    $dumper->dumpAssets();
}

// Middlewares
$app->before(function (Symfony\Component\HttpFoundation\Request $request) use ($app) {
    $app['twig']->addGlobal('_route', $request->get('_route'));
});

// Controllers
$app->get('/', function () use ($app) {
    $sessions = $app['db']->fetchAll('SELECT id, ip, starttime, endtime FROM sessions ORDER BY starttime DESC LIMIT 5');

    return $app['twig']->render('index.twig', array(
        'sessions' => $sessions
    )); 
})
->bind('index');

$app->get('/history/page/{page}', function ($page) use ($app) {
    $nbPages = ceil(($app['db']->fetchAssoc('SELECT COUNT(id) AS nbPages FROM sessions')['nbPages'])/10);
    $sessions = $app['db']->fetchAll('SELECT ip, starttime, endtime FROM sessions ORDER BY starttime DESC LIMIT ' . (($page-1)*10) . ', 10');

    return $app['twig']->render('history.twig', array(
        'nbPages' => $nbPages,
        'currentPage' => $page,
        'sessions' => $sessions
    ));
})
->bind('history');

$app->run();