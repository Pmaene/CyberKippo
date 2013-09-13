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

$countries = include_once __DIR__ . '/countries.php';

// Registering Service Providers
$app->register(new Igorw\Silex\ConfigServiceProvider(__DIR__ . '/../config/parameters.json'));

$app->register(new Silex\Provider\DoctrineServiceProvider(), array(
    'db.options' => array(
        'driver'    => $app['parameters']['database']['driver'],
        'host'      => $app['parameters']['database']['host'],
        'dbname'    => $app['parameters']['database']['dbname'],
        'user'      => $app['parameters']['database']['user'],
        'password'  => $app['parameters']['database']['password'],
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

// Helper Functions
function _getSessions($app, $nbSessions = 5, $startSessions = 0) {
    global $countries;

    $sessions = $app['db']->fetchAll('SELECT id, ip, starttime, endtime FROM sessions ORDER BY starttime DESC LIMIT ' . $startSessions . ', ' . $nbSessions);
    foreach ($sessions as $i => $session) {
        $sessions[$i]['starttime'] = new \DateTime($session['starttime']);
        $sessions[$i]['endtime'] = new \DateTime($session['endtime']);

        $auth = $app['db']->fetchAll('SELECT success, username, password, timestamp FROM auth WHERE session = ? ORDER BY timestamp DESC', array($session['id']));
        if (count($auth) > 0) {
            $sessions[$i]['auth'] = $auth;
            foreach ($sessions[$i]['auth'] as $j => $auth)
                $sessions[$i]['auth'][$j]['timestamp'] = new \DateTime($auth['timestamp']);
        }

        $nbCif = $app['db']->fetchAssoc('SELECT COUNT(id) as nbCif FROM cif WHERE session = ? AND reporttime > DATE_SUB(NOW(), INTERVAL ? DAY)', array($session['id'], 5))['nbCif'];
        if ($nbCif == 0) {
            foreach (_queryCif($session['ip']) as $cif) {
                $cif['detecttime'] = new \DateTime($cif['detecttime']);
                $cif['reporttime'] = new \DateTime($cif['reporttime']);

                $app['db']->insert(
                    'cif',
                    array(
                        'session'                   => $session['id'],
                        'purpose'                   => $cif['purpose'],
                        'asn'                       => $cif['asn'],
                        'asn_desc'                  => $cif['asn_desc'],
                        'portlist'                  => isset($cif['portlist']) ? $cif['portlist'] : null,
                        'rir'                       => $cif['rir'],
                        'alternativeid'             => $cif['alternativeid'],
                        'alternativeid_restriction' => $cif['alternativeid_restriction'],
                        'cc'                        => $cif['cc'],
                        'severity'                  => $cif['severity'],
                        'assessment'                => $cif['assessment'],
                        'description'               => $cif['description'],
                        'detecttime'                => $cif['detecttime']->format('Y-m-d H:i:s'),
                        'reporttime'                => $cif['reporttime']->format('Y-m-d H:i:s'),
                        'confidence'                => $cif['confidence'],
                        'restriction'               => $cif['restriction'],
                        'prefix'                    => $cif['prefix'],
                    )
                );
            }
        }

        $cif = $app['db']->fetchAll('SELECT * FROM cif WHERE session = ? AND confidence > ? AND reporttime > DATE_SUB(NOW(), INTERVAL ? DAY) GROUP BY alternativeid, detecttime ORDER BY detecttime DESC', array($session['id'], 80, 5));
        if (count($cif) > 0) {
            $sessions[$i]['cif'] = $cif;

            $reduceDates = array();
            $reducedCif = array();
            foreach ($sessions[$i]['cif'] as $j => $cif) {
                $sessions[$i]['cif'][$j]['detecttime'] = new \DateTime($cif['detecttime']);
                $sessions[$i]['cif'][$j]['reporttime'] = new \DateTime($cif['reporttime']);

                $sessions[$i]['cif'][$j]['country'] = isset($countries[$cif['cc']]) ? htmlentities($countries[$cif['cc']]) : 'Unknown';

                if (!isset($reduceDates[md5($cif['alternativeid'])]))
                    $reduceDates[md5($cif['alternativeid'])] = $sessions[$i]['cif'][$j]['detecttime'];

                if ($reduceDates[md5($cif['alternativeid'])] <= $sessions[$i]['cif'][$j]['detecttime']) {
                    $reduceDates[md5($cif['alternativeid'])] = $sessions[$i]['cif'][$j]['detecttime'];
                    $reducedCif[md5($cif['alternativeid'])] = $sessions[$i]['cif'][$j];
                }
            }

            $sessions[$i]['cif'] = $reducedCif;
        }
    }

    return $sessions;
}

function _queryCif($query) {
    $client = new Buzz\Client\FileGetContents();
    $client->setTimeout(60);

    $browser = new Buzz\Browser($client);
    $response = $browser->get(
        'http://' . $app['parameters']['cif']['host'] . '/api?apikey=' . $app['parameters']['cif']['api_key'] . '&q=' . $query,
        array('User-Agent' => 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36')
    );

    $objects = explode("\n", $response->getContent());
    foreach ($objects as $i => $object)
        $objects[$i] = (array) json_decode($object);
    return $objects;
}

// Controllers
$app->get('/', function () use ($app) {
    return $app['twig']->render('index.twig', array(
        'sessions' => _getSessions($app)
    )); 
})
->bind('index');

$app->get('/history/page/{page}', function ($page) use ($app) {
    $nbPages = ceil(($app['db']->fetchAssoc('SELECT COUNT(id) AS nbPages FROM sessions')['nbPages'])/10);

    return $app['twig']->render('history.twig', array(
        'nbPages' => $nbPages,
        'currentPage' => $page,
        'sessions' =>_getSessions($app, 10, ($page-1)*10)
    ));
})
->bind('history');

$app->run();
