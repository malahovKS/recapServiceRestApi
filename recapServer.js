var express = require('express'),
    multer = require('multer'),
    app = express(),
    exec = require('child_process').exec,
    fs = require('fs'),
    xml2js = require('xml2js'),
    request = require('request'),
    serveIndex = require('serve-index'),
    iconv = require('iconv-lite'),
    os = require('os');

//eyes module
inspect = require('eyes').inspector({maxLength: false});
//eyes module


//for basic auth with basic-auth module
var auth = require('./auth');
//for basic auth with basic-auth module

// winston A multi-transport async logging library for node.js
var winstonLog = require('./libs/log')(module);
// winston A multi-transport async logging library for node.js

//Character encoding auto-detection in JavaScript (port of python's chardet)
var jsChardet = require("jschardet");
//Character encoding auto-detection in JavaScript (port of python's chardet)

// for merging JSON Objects
var extend = require('util')._extend;
// for merging JSON Objects


// FOR PASSPORT LOGIN
/*--------------------------------------------------------------------------------------------------------------------*/
var passport = require('passport');
var Strategy = require('passport-local').Strategy;
var db = require('./dbForUsers');


// Configure the local strategy for use by Passport.
//
// The local strategy require a `verify` function which receives the credentials
// (`username` and `password`) submitted by the user.  The function must verify
// that the password is correct and then invoke `cb` with a user object, which
// will be set at `req.user` in route handlers after authentication.
passport.use(new Strategy(
    function (username, password, cb) {
        db.users.findByUsername(username, function (err, user) {
            if (err) {
                return cb(err);
            }
            if (!user) {
                return cb(null, false);
            }
            if (user.password != password) {
                return cb(null, false);
            }
            return cb(null, user);
        });
    }));

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  The
// typical implementation of this is as simple as supplying the user ID when
// serializing, and querying the user record by ID from the database when
// deserializing.
passport.serializeUser(function (user, cb) {
    cb(null, user.id);
});

passport.deserializeUser(function (id, cb) {
    db.users.findById(id, function (err, user) {
        if (err) {
            return cb(err);
        }
        cb(null, user);
    });
});
/*--------------------------------------------------------------------------------------------------------------------*/
// FOR PASSPORT LOGIN


//var request = require('request');

var bodyParser = require('body-parser');

var path = require("path");

var docExtension = '.doc';
var docxExtension = '.docx';
var txtExtension = '.txt';
var pdfExtension = '.pdf';

//ncp
var ncp = require('ncp').ncp;
ncp.limit = 70;
//ncp

var nameForNewRecapDir;


// nfriedly/express-rate-limit
var rateLimit = require('express-rate-limit');

var apiLimiter = new rateLimit({
        windowMs: 25000, // 25 sec
        max: 1, // limit each IP to 1 requests per windowMs
        delayMs: 0, // disable delaying - full speed until the max limit is reached
        message: 'Recap service is busy. Limit each IP to 1 request per 25 sec'
    }),
    apiLimiter10RequestsEach25Seconds = new rateLimit({
        windowMs: 10000, // 25 sec
        max: 10, // limit each IP to 1 requests per windowMs
        delayMs: 0, // disable delaying - full speed until the max limit is reached
        message: 'Recap service is busy. Limit each IP to 10 request per 25 sec'
    }),
    lemmaApiLimiter = new rateLimit({
        windowMs: 5000,
        delayMs: 0, // slow down subsequent responses by 3 seconds per request
        max: 10, // start blocking after 10 requests
        message: "Recap service is busy. Limit each IP to 10 request per 5 sec"
    }),
    apiLimiter10RequestsEach5Seconds = new rateLimit({
        windowMs: 5000,
        delayMs: 0, // slow down subsequent responses by 3 seconds per request
        max: 10, // start blocking after 10 requests
        message: "Recap service is busy. Limit each IP to 10 request per 5 sec"
    }),
    scholarApiLimiter = new rateLimit({
        windowMs: 2000,
        delayMs: 0, // slow down subsequent responses by 3 seconds per request
        max: 10, // start blocking after 5 requests
        message: "Recap service is busy. Limit each IP to 10 request per 2 sec"
    }),
// nfriedly/express-rate-limit

//multer
    upload = multer({dest: __dirname + '/uploads/'}).single('fileforanalysis');


// FOR PASSPORT LOGIN
/*--------------------------------------------------------------------------------------------------------------------*/
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(require('express-session')({secret: 'keyboard cat', resave: false, saveUninitialized: false}));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());
/*--------------------------------------------------------------------------------------------------------------------*/
// FOR PASSPORT LOGIN


// configure app to use bodyParser()
// this will let us get the data from a POST
app.use(bodyParser.urlencoded({limit: '50mb', extended: true}));
app.use(bodyParser.json({limit: '5mb'}));

//Gzip compressing can greatly decrease the size of the response body and hence increase the speed of a web app. Use the compression middleware for gzip compression in your Express app
var compression = require('compression');
app.use(compression());
//Gzip compressing can greatly decrease the size of the response body and hence increase the speed of a web app. Use the compression middleware for gzip compression in your Express app


/*
 disable X-Powered-By header
 If you don’t want to use Helmet, then at least disable the X-Powered-By header.
 Attackers can use this header (which is enabled by default) to detect apps running Express and then launch specifically-targeted attacks.
 So, best practice is to to turn off the header with the app.disable() method:
 */
app.disable('x-powered-by');
//disable X-Powered-By header


//log the IP of the client on each request
app.use(function (req, res, next) {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var filename = path.basename(req.url);
    winstonLog.info('[Client IP]:', ip + "    The API [" + filename + "] was requested.");
    next();
});
//log the IP of the client on each request

//Cross-Origin Resource Sharing (CORS) is a specification that enables truly open access across domain-boundaries.
//If you serve public content, please consider using CORS to open it up for universal JavaScript/browser access.
//For simple CORS requests, the server only needs to add the following header to its response:
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});
//For simple CORS requests, the server only needs to add the following header to its response:

var router = express.Router();              // get an instance of the express Router

// REGISTER OUR ROUTES -------------------------------all of our routes will be prefixed with /recapservice/api
//


app.use('/recapservice/api', router);


//--- обработка ошибок 404 и 500
app.use(function (req, res, next) {
    res.status(404);
    winstonLog.debug('Not found URL: %s', req.url);
    res.send({error: 'URL not found'});
});

// Internal Server Error; Generic error message when server fails
app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    winstonLog.error('Internal error(%d): %s', res.statusCode, err);
    res.send({InternalError: err + '. Code: ' + res.statusCode});
});
//--- обработка ошибок 404 и 500


//papers originals binary folder
router.use('/binary', auth.basicAuth('root', 'secret'), express.static(__dirname + '/papersBinary'));
//papers originals binary folder


// forUtf8ToWin1251Query folder
router.use('/Utf8ToWin1251', express.static(__dirname + '/queryFiles/forUtf8ToWin1251Query/'));
// forUtf8ToWin1251Query folder


//          CLIENT SIDES

//          DEBUG CLIENT SIDES
router.use('/clientSide', apiLimiter, auth.basicAuth('root', 'secrets'), express.static(__dirname + '/clientSide/form/'));
router.use('/gkgSearch', apiLimiter, auth.basicAuth('root', 'secrets'), express.static(__dirname + '/clientSide/googleKnowledgeGraph/'));
router.use('/logDir', apiLimiter,auth.basicAuth('root', 'secrets'), serveIndex('./logs/', {'icons': true}));
router.use('/cv', apiLimiter10RequestsEach25Seconds, express.static(__dirname + '/alexandr/'));
router.use('/dicApp', auth.basicAuth('root', 'dictionary'), express.static(__dirname + '/dictionary/app_server/'));
router.use('/dicOntMobile', auth.basicAuth('root', 'dictionary'), express.static(__dirname + '/dictionary/mobile_app_server/'));
//          DEBUG CLIENT SIDES


router.get('/login',
    function (req, res) {
        res.render('login');
    });

router.get('/home',
    function (req, res) {
        res.render('home', {user: req.user});
    });

router.post('/login',
    passport.authenticate('local', {failureRedirect: '/recapservice/api/login'}),
    function (req, res) {
        res.redirect('/recapservice/api/clientside');
    });

//          CLIENT SIDES


router.get('/docs', auth.basicAuth('root', 'secrets'), function (req, res) {
    winstonLog.info('[docs query]');
    res.sendFile(__dirname + '/TextForTestHelp/api.json');
});

// Get most recent logfile
router.get('/logfile', function (req, res) {
    fs.readdir(__dirname + '/logs/', function (err, files) {
        if (err) return;
        getNewestFile(__dirname + '/logs/', files, function (newestFile) {
            winstonLog.info('Most recent [logfile query]: ' + newestFile.file);
            res.sendFile(newestFile.file);
        });
    });
});
// Get most recent logfile

/*--------------------------------------------------------------------------------------------------------------------*/
//TODO DICTIONARY
router.get('/dictionary', apiLimiter10RequestsEach5Seconds, function (req, res) {

    fs.readFile('dictionary/petrenkoDictionaryClean.json', function (err, data) {
        if (err) {
            winstonLog.error(err + '. Error code: ' + err.code);
            res.status(500).json({error: err.code});
        }
        var dictionaryObj = JSON.parse(data);
        res.json(dictionaryObj);
    });
});
/*--------------------------------------------------------------------------------------------------------------------*/
//TODO Update help
//              GET /HELP SERVICE
router.get('/help', function (req, res) {
    winstonLog.info('[GET HELP]');
    res.json({
        "recapService": {
            "API": [
                {
                    "txt": {
                        "Route": "http://icybcluster.org.ua:32145/recapservice/api/txt",
                        "HTTP Verb": "POST",
                        "Body": "form-data",
                        "key": "fileforanalysis",
                        "value": "file",
                        "file encoding": "Windows-1251",
                        "Description": "Send .txt file to parse with recap service",
                        "Output Data": "XML data includes content of allterms.xml, unknown.txt and parce.xml",
                        "Limits": "each IP to 10 request per 25 sec"
                    }
                },
                {
                    "txtJson": {
                        "Route": "http://icybcluster.org.ua:32145/recapservice/api/txtJson",
                        "HTTP Verb": "POST",
                        "Body": "form-data",
                        "key": "fileforanalysis",
                        "value": "file",
                        "file encoding": "Windows-1251",
                        "Description": "Send .txt file to parse with recap service",
                        "Output Data": "JSON data includes recap and content of unknown.txt",
                        "Limits": "each IP to 10 request per 25 sec"
                    }
                },
                {
                    "docdocxJson": {
                        "Route": "http://icybcluster.org.ua:32145/recapservice/api/docdocxJson",
                        "HTTP Verb": "POST",
                        "Body": "form-data",
                        "key": "fileforanalysis",
                        "value": "file",
                        "Description": "Send .doc or .docx file to parse with recap service",
                        "Output Data": "JSON data includes recap and content of unknown.txt",
                        "Limits": "each IP to 10 request per 25 sec"
                    }
                },
                {
                    "pdfJson": {
                        "Route": "http://icybcluster.org.ua:32145/recapservice/api/pdfJson",
                        "HTTP Verb": "POST",
                        "Body": "form-data",
                        "key": "fileforanalysis",
                        "value": "file",
                        "Description": "Send .pdf file to parse with recap service",
                        "Output Data": "JSON data includes recap and content of unknown.txt",
                        "Limits": "each IP to 10 request per 25 sec"
                    }
                },
                {
                    "pdf": {
                        "Route": "http://icybcluster.org.ua:32145/recapservice/api/pdf",
                        "HTTP Verb": "POST",
                        "Body": "form-data",
                        "key": "fileforanalysis",
                        "value": "file",
                        "Description": "Send .pdf file to parse with recap service",
                        "Output Data": "JSON data includes recap for OBZP NDk",
                        "Limits": "each IP to 10 request per 25 sec"
                    }
                },
                {
                    "lemma": {
                        "Route": "http://icybcluster.org.ua:32145/recapservice/api/lemma",
                        "HTTP Verb": "POST",
                        "Body": "x-www-form-urlencoded",
                        "key": "query",
                        "value": "text of query",
                        "Description": "lemmatization words service for the Ukrainian language",
                        "Output Data": "XML data",
                        "Limits": "each IP to 10 request per 5 sec"
                    }
                },
                {
                    "utf8ToWin1251": {
                        "Route": "http://icybcluster.org.ua:32145/recapservice/api/utf8ToWin1251",
                        "HTTP Verb": "POST",
                        "Body": "x-www-form-urlencoded",
                        "key": "query",
                        "value": "text of query",
                        "Description": "Text converting service",
                        "Input Data": "Text data in UTF8",
                        "Output Data": "Text data in Windows-1251",
                        "Limits": "each IP to 10 request per 5 sec"
                    }
                },
                {
                    "dictionary": {
                        "Route": "http://icybcluster.org.ua:32145/recapservice/api/dictionary",
                        "HTTP Verb": "GET",
                        "Description": "Dictionary in JSON"
                    }
                },
                {
                    "Route": "http://icybcluster.org.ua:32145/recapservice/api/help",
                    "HTTP Verb": "GET",
                    "Description": "API help"
                },
                {
                    "Route": "http://icybcluster.org.ua:32145/recapservice/api/logfile",
                    "HTTP Verb": "GET",
                    "Description": "Recap service logs"
                },
                {
                    "Route": "http://icybcluster.org.ua:32145/recapservice/api/docs/api.json",
                    "HTTP Verb": "GET",
                    "Description": "Retrieve file with old documentation"
                }
            ]
        }
    });
});
//              GET /HELP SERVICE

//              POST /PDFMONGODB SERVICE
/*router.post('/pdfmongodb', upload, apiLimiter, function (req, res, next) {

 var receiveHeadersPdfMongodb = req.headers;
 winstonLog.debug('[Title filed]: ' + receiveHeadersPdfMongodb.title);
 winstonLog.debug(inspect(req.headers));

 winstonLog.debug(req.file);
 winstonLog.debug('filename = ' + req.file.filename);
 winstonLog.debug('originalName = ' + req.file.originalname);
 winstonLog.debug('path = ' + req.file.path);

 var stringForIndexPdf = req.file.originalname;

 // PDFTOTEXT UTILITY

 if (stringForIndexPdf.indexOf(pdfExtension) != -1) {

 winstonLog.debug('extension of uploaded file = .pdf');

 var nameForPapersBinaryPdf = Date.now()+'_'+req.file.originalname;
 nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';

 ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }

 winstonLog.debug('Copy /rootconsole2016/ to /consoles done!');
 winstonLog.debug('Prepare to start Konspekt >> childConverterPDF');

 //});

 //save papers originals
 ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryPdf, function (err) {
 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }
 winstonLog.info('[PDF] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryPdf);

 });
 //save papers originals

 ncp(req.file.path, __dirname + nameForNewRecapDir + req.file.originalname, function (err) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }


 //});

 var childConverterPdf = exec("pdftotext " +'"'+ __dirname + nameForNewRecapDir + req.file.originalname +'"'+' ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {timeout: 180000},
 function (err, stdout) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 winstonLog.error(err.stack);
 winstonLog.error('Error code: ' + err.code);
 winstonLog.error('Signal received: ' + err.signal);
 return next(err);
 }

 winstonLog.debug(stdout);

 // PDF READ/WRITE FILES ASYNC
 fs.readFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {encoding: "UTF-8"}, function (err, data) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }

 winstonLog.info('[PDF]+[fileForAnalysisPdf.txt] It\'s read!');

 var outputFileTxtInCP1251 = iconv.encode(data, "win1251");

 fs.writeFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', outputFileTxtInCP1251, function (err) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }

 winstonLog.info('[PDF]+[fileForAnalysisPdfCP1251.txt] It\'s saved!');

 });
 });
 // PDF READ/WRITE FILES ASYNC

 });

 childConverterPdf.on('exit', function (code) {
 winstonLog.debug('Child process [childConverterPdf] exited with exit code ' + code);
 });


 var childRecapPdf = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', {
 timeout: 180000,
 maxBuffer: 400 * 1024
 },
 function (err, stdout) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 winstonLog.error(err.stack);
 winstonLog.error('Error code: ' + err.code);
 winstonLog.error('Signal received: ' + err.signal);
 return next(err);
 }

 winstonLog.debug('[childRecapPdf] done!');
 winstonLog.debug(stdout);


 // PDF READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS
 fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {

 if (err) {
 winstonLog.error('[PDF]+[allterms.xml]' + err);
 return next(err);
 }
 winstonLog.info('[PDF]+[allterms.xml] It\'s read!');

 var outputFileAlltermsInUtf8Pdf = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

 fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInUtf8Pdf, function (err) {

 if (err) {
 winstonLog.debug('[PDF]+alltermsUTF8.xml' + err);
 return next(err);
 }

 winstonLog.info('[PDF]+[alltermsUTF8.xml] It\'s saved!');

 var parserPdf = new xml2js.Parser({strict: false, explicitArray: true, ignoreAttrs: true}); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.

 fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

 if (err) {
 winstonLog.error('[PDF]+[alltermsUTF8.xml]' + err);
 return next(err);
 }

 parserPdf.parseString(data, function (err, result) {

 if (err) {
 // something went wrong
 winstonLog.error('[parserPdf]' + err);
 return next(err);
 }

 winstonLog.info('[PDF] xml2js.Parser {strict: false, explicitArray: true, ignoreAttrs: true}');
 winstonLog.debug(inspect(result));
 fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

 if (err) {
 // something went wrong, file probably not written.
 winstonLog.error(err);
 return next(err);
 }

 fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
 if (err == null) {
 winstonLog.debug('[PDF]+[alltermsUTF8.json] File exists');
 fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
 if (error) {
 winstonLog.error(error);
 res.writeHead(500);
 res.end();
 } else {
 //delete tmp file from uploads directory
 fs.unlink(req.file.path);
 winstonLog.debug('tmp file deleted from uploads directory');
 //delete tmp file from uploads directory
 winstonLog.debug('Sending json to client!');


 //mongoDB
 var mongoDBFlag = false;
 var MongoClient = require('mongodb').MongoClient;
 var url = 'mongodb://marchenkov:1234567890@ds013260.mlab.com:13260/personified';
 MongoClient.connect(url, function(err, db) {
 if (err) {
 winstonLog.error('[MongoDB] Some other error: ', err.code);
 return next(err);
 }
 db.collection('marchenkovpapers').insertOne(result, function(err, r) {
 if (err) {
 winstonLog.error('[MongoDB] Some other error: ', err.code);
 return next(err);
 }
 mongoDBFlag = true;
 winstonLog.info('[MongoDB] OK');
 res.type('application/json');
 res.set({
 'mongoDBFlag': mongoDBFlag,
 'url': 'http://icybcluster.org.ua:33145/recapservice/api/binary/'+ encodeURI(nameForPapersBinaryPdf)
 });
 res.send(content);
 });

 });
 //mongoDB

 }
 });
 } else if (err.code == 'ENOENT') {
 winstonLog.error('ENOENT');
 return next(err);
 } else {
 winstonLog.error('Some other error: ', err.code);
 return next(err);
 }
 });

 });
 winstonLog.debug('[parserPdf] XML to JSON convert Done');
 });
 });

 });
 });
 // PDF READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS


 });

 childRecapPdf.on('exit', function (code) {
 winstonLog.debug('Child process [childRecapPdf] exited with exit code ' + code);
 });
 });
 });


 } else {

 //WRONG FILE FORMAT

 res.writeHead(200, {'Content-Type': 'text/plain'});
 winstonLog.debug('Wrong file extension! Must be .pdf');
 res.end('Wrong file extension! Must be .pdf');
 fs.unlink(req.file.path);

 //WRONG FILE FORMAT

 }

 // PDFTOTEXT UTILITY

 });*/
//              POST /PDFMONGODB SERVICE


//              POST /PDFRUUK TRANSLATOR RU-UK SERVICE
/*router.post('/pdfruuk', upload, apiLimiter, function (req, res, next) {

    var receiveHeadersPdfTranslateRuUk = req.headers;
    winstonLog.debug('[pdfTranslator] ' + inspect(receiveHeadersPdfTranslateRuUk));

    winstonLog.debug('[pdfTranslator] ' + req.file);
    winstonLog.debug('[pdfTranslator] filename = ' + req.file.filename);
    winstonLog.debug('[pdfTranslator] originalName = ' + req.file.originalname);
    winstonLog.debug('[pdfTranslator] path = ' + req.file.path);

    var stringForIndexPdfTranslateRuUk = req.file.originalname;

    //for tconspectus
    var tconspectusSummary;
    var summaryPDFRUUK = '';
    //for tconspectus

    // PDFTOTEXT UTILITY

    if (stringForIndexPdfTranslateRuUk.indexOf(pdfExtension) != -1) {

        winstonLog.debug('[pdfTranslator] extension of uploaded file = .pdf');

        var nameForPapersBinaryPdfTranslateRuUk = Date.now() + '_' + req.file.originalname;
        nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';

        ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {

            if (err) {
                winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                return next(err);
            }

            winstonLog.debug('[pdfTranslator] Copy /rootconsole2016/ to /consoles done!');
            winstonLog.debug('[pdfTranslator] Prepare to start Konspekt >> childConverterPDF');

            //});

//save papers originals
            ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryPdfTranslateRuUk, function (err) {
                if (err) {
                    winstonLog.error('[pdftranslateruuk] Internal error(%d): %s', res.statusCode, err);
                    return next(err);
                }
                winstonLog.info('[pdfTranslator] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryPdfTranslateRuUk);

            });
//save papers originals

            ncp(req.file.path, __dirname + nameForNewRecapDir + req.file.originalname, function (err) {

                if (err) {
                    winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                    return next(err);
                }


                //});

                var childConverterPdfTranslateRuUk = exec("pdftotext " + '"' + __dirname + nameForNewRecapDir + req.file.originalname + '"' + ' ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {timeout: 180000},
                    function (err, stdout) {

                        if (err) {
                            winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                            winstonLog.error('[pdfTranslator]' + err.stack);
                            winstonLog.error('[pdfTranslator] Error code: ' + err.code);
                            winstonLog.error('[pdfTranslator] Signal received: ' + err.signal);
                            return next(err);
                        }

                        winstonLog.debug(stdout);


                        // PDF READ/WRITE FILES ASYNC
                        fs.readFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {encoding: "UTF-8"}, function (err, data) {

                            if (err) {
                                winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                                return next(err);
                            }


                            winstonLog.debug('[pdfTranslator] Word count in the file= ' + data.length);

                            var wordCountPdfTranslator = data.length;

                            if (wordCountPdfTranslator < 10000) {

                                //POST TO YANDEX.TRANSLATE
                                request.post({
                                    url: 'https://translate.yandex.net/api/v1.5/tr.json/detect',
                                    rejectUnauthorized: false,
                                    form: {
                                        key: 'trnsl.1.1.20160517T143002Z.e9fc37c7a484c5f4.8cba036cc3eb084c401f3766ed5b2b389b6dc9fc',
                                        hint: 'ru,uk', text: data
                                    }
                                }, function (err, httpResponse, body) {
                                    if (err) {
                                        winstonLog.error('[pdfTranslator] Internal error: ', err);
                                        winstonLog.error('[pdfTranslator]' + err.stack);
                                        winstonLog.error('[pdfTranslator] Error code: ' + err.code);
                                        winstonLog.error('[pdfTranslator] Signal received: ' + err.signal);
                                    }
                                    var yandexTranslatePdfLang = body;
                                    yandexTranslatePdfLang = JSON.parse(yandexTranslatePdfLang);

                                    if (yandexTranslatePdfLang.lang == 'ru') {

                                        winstonLog.debug('[pdfTranslator] Pdf Lang= ' + body);

                                        ////////////////////////////////////////////////////////////
                                        //TCONSPECTUS
                                        var textForTconspectus = data.replace(/\r?\n|\r/g, " ");
                                        //replace(/(\r\n|\n|\r)/gm," ");

                                        tConspectusRu(textForTconspectus.trim(), function (ruSummaryTconspectusCallback, errorReq) {
                                            if (errorReq) {
                                                winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                                                return next(errorReq);
                                            }
                                            winstonLog.debug('[pdfTranslator] [tconspectusSummary]: \n' + ruSummaryTconspectusCallback);
                                            summaryPDFRUUK = ruSummaryTconspectusCallback;

                                        });

                                        // Форматирование такста на вход t-conspectus!!!
                                        //TCONSPECTUS
                                        ////////////////////////////////////////////////////////////


                                        request.post({
                                            url: 'https://translate.yandex.net/api/v1.5/tr.json/translate',
                                            rejectUnauthorized: false,
                                            form: {
                                                key: 'trnsl.1.1.20160517T143002Z.e9fc37c7a484c5f4.8cba036cc3eb084c401f3766ed5b2b389b6dc9fc',
                                                ui: 'ru', lang: 'ru-uk', text: data
                                            }
                                        }, function (err, httpResponse, bodyRu) {
                                            if (err) {
                                                winstonLog.error('[pdfTranslator] Internal error: ', err);
                                                winstonLog.error('[pdfTranslator]' + err.stack);
                                                winstonLog.error('[pdfTranslator] Error code: ' + err.code);
                                                winstonLog.error('[pdfTranslator] Signal received: ' + err.signal);
                                            }
                                            winstonLog.debug(bodyRu);
                                            var yandexTranslateResponsePdf = bodyRu;
                                            yandexTranslateResponsePdf = JSON.parse(yandexTranslateResponsePdf);
                                            winstonLog.debug(yandexTranslateResponsePdf.text[0]);

                                            winstonLog.info('[pdfTranslator]+[fileForAnalysisPdf.txt] It\'s read!');

                                            var outputFileTxtInCP1251 = iconv.encode(yandexTranslateResponsePdf.text[0], "win1251");

                                            fs.writeFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', outputFileTxtInCP1251, function (err) {

                                                if (err) {
                                                    winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                                                    return next(err);
                                                }

                                                winstonLog.info('[pdfTranslator]+[fileForAnalysisPdfCP1251.txt] It\'s saved!');

                                            });
                                        });

                                    } else {
                                        winstonLog.debug('[pdfTranslator] Pdf Lang= ' + body);

                                        var outputFileTxtInCP1251 = iconv.encode(data, "win1251");

                                        fs.writeFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', outputFileTxtInCP1251, function (err) {

                                            if (err) {
                                                winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                                                return next(err);
                                            }

                                            winstonLog.info('[pdfTranslator]+[fileForAnalysisPdfCP1251.txt] It\'s saved!');

                                        });

                                    }

                                });
                            } else {
                                request.post({
                                    url: 'https://translate.yandex.net/api/v1.5/tr.json/detect',
                                    rejectUnauthorized: false,
                                    form: {
                                        key: 'trnsl.1.1.20160517T143002Z.e9fc37c7a484c5f4.8cba036cc3eb084c401f3766ed5b2b389b6dc9fc',
                                        hint: 'ru,uk', text: data
                                    }
                                }, function (err, httpResponse, body) {
                                    if (err) {
                                        winstonLog.error('[pdfTranslator] Internal error: ', err);
                                        winstonLog.error('[pdfTranslator]' + err.stack);
                                        winstonLog.error('[pdfTranslator] Error code: ' + err.code);
                                        winstonLog.error('[pdfTranslator] Signal received: ' + err.signal);
                                    }

                                    var yandexTranslatePdfLang = body;
                                    yandexTranslatePdfLang = JSON.parse(yandexTranslatePdfLang);

                                    winstonLog.debug('[pdfTranslator] Pdf Lang= ' + body);

                                    if (yandexTranslatePdfLang.lang == 'uk') {

                                        var outputFileTxtInCP1251 = iconv.encode(data, "win1251");

                                        fs.writeFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', outputFileTxtInCP1251, function (err) {

                                            if (err) {
                                                winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                                                return next(err);
                                            }

                                            winstonLog.info('[pdfTranslator]+[fileForAnalysisPdfCP1251.txt] It\'s saved!');

                                        });
                                    } else {
                                        //now it's error
                                        winstonLog.error('[pdfTranslator] [Error]  Word count limit to translate = 10000');
                                        return next('[pdfTranslator] [Error]  Word count limit to translate = 10000');
                                    }
                                });
                            }
                        });
                        // PDF READ/WRITE FILES ASYNC

                    });

                childConverterPdfTranslateRuUk.on('exit', function (code) {
                    winstonLog.debug('[pdfTranslator] Child process [childConverterPdf] exited with exit code ' + code);
                });


                var childRecapPdfTranslateRuUk = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', {
                        timeout: 180000,
                        maxBuffer: 400 * 1024
                    },
                    function (err, stdout) {

                        if (err) {
                            winstonLog.error('[pdfTranslator] Internal error(%d): %s', res.statusCode, err);
                            winstonLog.error(err.stack);
                            winstonLog.error('[pdfTranslator] Error code: ' + err.code);
                            winstonLog.error('[pdfTranslator] Signal received: ' + err.signal);
                            return next(err);
                        }

                        winstonLog.debug('[pdfTranslator] [childRecapPdf] done!');
                        winstonLog.debug(stdout);


                        // PDF READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS
                        fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {

                            if (err) {
                                winstonLog.error('[pdfTranslator]+[allterms.xml]' + err);
                                return next(err);
                            }
                            winstonLog.info('[pdfTranslator]+[allterms.xml] It\'s read!');

                            var outputFileAlltermsInUtf8PdfTranslateRuUk = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

                            fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInUtf8PdfTranslateRuUk, function (err) {

                                if (err) {
                                    winstonLog.debug('[pdfTranslator]+alltermsUTF8.xml' + err);
                                    return next(err);
                                }

                                winstonLog.info('[pdfTranslator]+[alltermsUTF8.xml] It\'s saved!');

                                var parserPdfTranslateRuUk = new xml2js.Parser({
                                    strict: false,
                                    explicitArray: true,
                                    ignoreAttrs: true
                                }); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.

                                fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

                                    if (err) {
                                        winstonLog.error('[pdfTranslator]+[alltermsUTF8.xml]' + err);
                                        return next(err);
                                    }

                                    parserPdfTranslateRuUk.parseString(data, function (err, result) {

                                        if (err) {
                                            // something went wrong
                                            winstonLog.error('[pdfTranslator] [parserPdf]' + err);
                                            return next(err);
                                        }

                                        winstonLog.info('[pdfTranslator] xml2js.Parser {strict: false, explicitArray: true, ignoreAttrs: true}');
                                        winstonLog.debug(inspect(result));
                                        fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

                                            if (err) {
                                                // something went wrong, file probably not written.
                                                winstonLog.error(err);
                                                return next(err);
                                            }

                                            fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
                                                if (err == null) {
                                                    winstonLog.debug('[pdfTranslator]+[alltermsUTF8.json] File exists');
                                                    fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
                                                        if (error) {
                                                            winstonLog.error(error);
                                                            res.writeHead(500);
                                                            res.end();
                                                        }
                                                        else {
                                                            //delete tmp file from uploads directory
                                                            fs.unlink(req.file.path);
                                                            winstonLog.debug('[pdfTranslator] tmp file deleted from uploads directory');
                                                            //delete tmp file from uploads directory
                                                            winstonLog.debug('[pdfTranslator] Sending json to client!');

                                                            res.type('application/json');
                                                            res.set({
                                                                'url': 'http://icybcluster.org.ua:33145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryPdfTranslateRuUk),
                                                                'summary': encodeURI(summaryPDFRUUK)
                                                            });
                                                            res.send(content);
                                                        }
                                                    });
                                                } else if (err.code == 'ENOENT') {
                                                    winstonLog.error('ENOENT');
                                                    return next(err);
                                                } else {
                                                    winstonLog.error('[pdfTranslator] Some other error: ', err.code);
                                                    return next(err);
                                                }
                                            });

                                        });
                                        winstonLog.debug('[pdfTranslator] [parserPdf] XML to JSON convert Done');
                                    });
                                });

                            });
                        });
                        // PDF READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS


                    });

                childRecapPdfTranslateRuUk.on('exit', function (code) {
                    winstonLog.debug('[pdfTranslator] Child process [childRecapPdf] exited with exit code ' + code);
                });
            });
        });


    } else {

        //WRONG FILE FORMAT

        res.set('Content-Type', 'text/plain');
        winstonLog.debug('[pdfTranslator] Wrong file extension! Must be .pdf');
        res.end('[pdfTranslator] Wrong file extension! Must be .pdf');
        fs.unlink(req.file.path);

        //WRONG FILE FORMAT

    }

    // PDFTOTEXT UTILITY

});*/
//              POST /PDFTRANSLATOR SERVICE


//              POST /PDF SERVICE
router.post('/pdf', upload, apiLimiter, function (req, res, next) {

    if (upload.filename == null || upload.filename == undefined) {
        winstonLog.error('[PDF] upload.filename == null || upload.filename == undefined');
    }

    var receiveHeadersPdf = req.headers;
    winstonLog.debug('[PDF] inspect(receiveHeadersPdf) ' + inspect(receiveHeadersPdf));

    winstonLog.debug('[PDF] req.file = ' + req.file);
    winstonLog.debug('[PDF] filename = ' + req.file.filename);
    winstonLog.debug('[PDF] originalName = ' + req.file.originalname);
    winstonLog.debug('[PDF] path = ' + req.file.path);

    var stringForIndexPdf = req.file.originalname;


    // PDFTOTEXT UTILITY
    if (stringForIndexPdf.indexOf(pdfExtension) == -1) {

        //WRONG FILE FORMAT
        winstonLog.error('[PDF] Wrong file extension! Must be .pdf');
        res.status(400).json({error: '[PDF] Wrong file extension! Must be .pdf'});
        fs.unlink(req.file.path);
        //WRONG FILE FORMAT

    } else {

        winstonLog.debug('[PDF] extension of uploaded file = .pdf');

        var simpleSummaryOfPdf = 'Summary'; // For otsUA function
        var htmlSummaryOfPdf = 'Html summary';
        var keywordsSummaryOfPdf = 'Keywords summary';
        var pdfPagesCount = 'Pdf pages count';
        var pdfTitle = 'Pdf title';

        var nameForPapersBinaryPdf = Date.now() + '_' + req.file.originalname;
        nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';

        ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {

            if (err) {
                winstonLog.error('[PDF] Internal error(%d): %s', res.statusCode, err);
                return next(err);
            }

            winstonLog.debug('[PDF] Copy /rootconsole2016/ to /consoles done!');
            winstonLog.debug('[PDF] Prepare to start Konspekt >> childConverterPDF');


//save papers originals
            ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryPdf, function (err) {
                if (err) {
                    winstonLog.error('[PDF] Internal error(%d): %s', res.statusCode, err);
                    return next(err);
                }
                winstonLog.info('[PDF] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryPdf);

            });
//save papers originals

            ncp(req.file.path, __dirname + nameForNewRecapDir + req.file.originalname, function (err) {

                if (err) {
                    winstonLog.error('[PDF] Internal error(%d): %s', res.statusCode, err);
                    return next(err);
                }


                // PDF INFO
                // Get pages count from pdf
                var childPdfInfo = exec("pdfinfo " + '"' + __dirname + nameForNewRecapDir + req.file.originalname + '"' + " | grep Pages | awk '{print $2}'", {timeout: 120000},
                    function (err, stdout) {
                        if (err) {
                            winstonLog.error('[PDF] Internal error(%d): %s', err);
                            winstonLog.error(err.stack);
                            winstonLog.error('[PDF] Error code: ' + err.code);
                            winstonLog.error('[PDF] Signal received: ' + err.signal);
                            return next(err);
                        }
                        winstonLog.debug('[PDF] Child process [childPdfInfo] \n' + stdout);
                    });
                childPdfInfo.on('exit', function (code) {
                    winstonLog.debug('[PDF] Child process [childPdfInfo] exited with exit code ' + code);
                });
                childPdfInfo.stdout.on('data', function (pdfInfoOutput) {
                    pdfPagesCount = pdfInfoOutput;
                    pdfPagesCount = pdfPagesCount.trim();
                });

                // Get pdf title
                var childPdfInfoTitle = exec('env LC_ALL=uk_UA.UTF-8 java -jar ' + __dirname + '/pdfInspector/docears-pdf-inspector.jar -title ' + '"' + __dirname + nameForNewRecapDir + req.file.originalname + '"', {timeout: 120000},
                    function (err, stdout) {
                        if (err) {
                            winstonLog.error('[PDF] Internal error(%d): %s', err);
                            winstonLog.error(err.stack);
                            winstonLog.error('[PDF] Error code: ' + err.code);
                            winstonLog.error('[PDF] Signal received: ' + err.signal);
                            return next(err);
                        }
                        winstonLog.debug('[PDF] Child process [childPdfInfoTitle] \n' + stdout);
                        pdfTitle = stdout;
                    });
                childPdfInfoTitle.on('exit', function (code) {
                    winstonLog.debug('[PDF] Child process [childPdfInfoTitle] exited with exit code ' + code);
                });
                childPdfInfoTitle.stdout.on('data', function (pdfInfoTitleOutput) {
                    pdfTitle = pdfInfoTitleOutput;
                    //pdfTitle = pdfTitle.trim();
                });
                // PDF INFO

                var childConverterPdf = exec("pdftotext -layout -nopgbrk -raw -eol unix " + '"' + __dirname + nameForNewRecapDir + req.file.originalname + '"' + ' ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {timeout: 120000},
                    //var childConverterPdf = exec("pdftotext -nopgbrk -raw -eol unix " + '"' + __dirname + nameForNewRecapDir + req.file.originalname + '"' + ' ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {timeout: 200000},
                    function (err, stdout) {

                        if (err) {
                            winstonLog.error('[PDF] Internal error(%d): %s', err);
                            winstonLog.error(err.stack);
                            winstonLog.error('[PDF] Error code: ' + err.code);
                            winstonLog.error('[PDF] Signal received: ' + err.signal);
                            return next(err);
                        }

                    });

                childConverterPdf.on('exit', function (code) {

                    winstonLog.debug('[PDF] Child process [childConverterPdf] exited with exit code ' + code);

                    /*
                     //Character encoding auto-detection in JavaScript (port of python's chardet)
                     fs.readFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', function (err, data) {
                     if (err) {
                     winstonLog.error('[PDF] Internal error(%d): %s', res.statusCode, err);
                     }
                     var encoding = jsChardet.detect(data).encoding.toLowerCase();
                     winstonLog.debug('[Text encoding]' + encoding);
                     });
                     //Character encoding auto-detection in JavaScript (port of python's chardet)
                     */

                    // PDF READ/WRITE FILES ASYNC
                    fs.readFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {encoding: "UTF-8"}, function (err, data) {

                        if (err) {
                            winstonLog.error('[PDF] Internal error(%d): %s', res.statusCode, err);
                            return next(err);
                        }

                        winstonLog.info('[PDF]+[fileForAnalysisPdf.txt] It\'s read!');


                        var outputFileTxtInCP1251 = iconv.encode(data, "win1251");

                        fs.writeFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', outputFileTxtInCP1251, function (err) {

                            if (err) {
                                winstonLog.error('[PDF] Internal error(%d): %s', res.statusCode, err);
                                return next(err);
                            }

                            winstonLog.info('[PDF]+[fileForAnalysisPdfCP1251.txt] It\'s saved!');

                        });
                    });
                    // PDF READ/WRITE FILES ASYNC

                    //Make summary of the article with OTS function
                    otsForUaTextsWithSimpleOutput(__dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', function (summaryOut) {
                        simpleSummaryOfPdf = summaryOut;
                        simpleSummaryOfPdf = simpleSummaryOfPdf.trim();
                        //This javascript replaces all 3 types of line breaks with a space
                        // simpleSummaryOfPdf = simpleSummaryOfPdf.replace(/^(?=\n)$|^\s*|\s*$|\n\n+/gm,'');
                        //simpleSummaryOfPdf = simpleSummaryOfPdf.replace(/(\r\n|\n|\r)/gm," ");
                    });

                    otsForUaTextsWithHtmlOutput(__dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', function (summaryHtmlOut) {
                        htmlSummaryOfPdf = summaryHtmlOut;
                        htmlSummaryOfPdf = htmlSummaryOfPdf.trim();
                    });

                    otsForUaTextsWithKeywordsOutput(__dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', function (summaryKeywordsOut) {
                        keywordsSummaryOfPdf = summaryKeywordsOut;
                        keywordsSummaryOfPdf = keywordsSummaryOfPdf.split(/"/)[1];
                    });
                    //Make summary of the article with OTS function

                });


                var childRecapPdf = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', {
                        timeout: 120000,
                        maxBuffer: 400 * 1024
                    },
                    function (err, stdout) {

                        if (err) {
                            winstonLog.error('[PDF]Internal error(%d): %s', err);
                            winstonLog.error(err.stack);
                            winstonLog.error('[PDF] Error code: ' + err.code);
                            winstonLog.error('[PDF] Signal received: ' + err.signal);
                            return next(err);
                        }

                    });

                childRecapPdf.on('exit', function (code) {

                    winstonLog.debug('[PDF] Child process [childRecapPdf] exited with exit code ' + code);
                    winstonLog.debug('[PDF] [childRecapPdf] done!');

                    // PDF READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS
                    fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {

                        if (err) {
                            winstonLog.error('[PDF]+[allterms.xml]' + err);
                            return next(err);
                        }
                        winstonLog.info('[PDF]+[allterms.xml] It\'s read!');

                        var outputFileAlltermsInUtf8Pdf = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

                        fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInUtf8Pdf, function (err) {

                            if (err) {
                                winstonLog.debug('[PDF]+alltermsUTF8.xml' + err);
                                return next(err);
                            }

                            winstonLog.info('[PDF]+[alltermsUTF8.xml] It\'s saved!');

                            var parserPdf = new xml2js.Parser({
                                strict: false,
                                explicitArray: true,
                                ignoreAttrs: true
                            }); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.

                            fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

                                if (err) {
                                    winstonLog.error('[PDF]+[alltermsUTF8.xml]' + err);
                                    return next(err);
                                }

                                parserPdf.parseString(data, function (err, result) {

                                    if (err) {
                                        // something went wrong
                                        winstonLog.error('[PDF] [parserPdf]' + err);
                                        return next(err);
                                    }

                                    winstonLog.info('[PDF] xml2js.Parser {strict: false, explicitArray: true, ignoreAttrs: true}');
                                    winstonLog.debug(inspect(result));

                                    //here need to insert idlog and htmlSummaryOfPdf inside alltermsUTF8.json

                                    //

                                    fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

                                        if (err) {
                                            // something went wrong, file probably not written.
                                            winstonLog.error('[PDF] ' + err);
                                            return next(err);
                                        }

                                        fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
                                            if (err == null) {
                                                winstonLog.debug('[PDF]+[alltermsUTF8.json] File exists');
                                                fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
                                                    if (error) {
                                                        winstonLog.error(error);
                                                        res.status(500).json({error: '[PDF]' + error});
                                                        fs.unlink(req.file.path);
                                                    } else {
                                                        //delete tmp file from uploads directory
                                                        fs.unlink(req.file.path);
                                                        winstonLog.debug('[PDF] tmp file deleted from uploads directory');
                                                        //delete tmp file from uploads directory
                                                        winstonLog.debug('[PDF] Sending json to client!');

                                                        res.type('application/json');
                                                        res.set({
                                                            'url': 'http://icybcluster.org.ua:32145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryPdf),
                                                            'summary': encodeURI(simpleSummaryOfPdf),
                                                            'summaryHtml': encodeURI(htmlSummaryOfPdf),
                                                            'summaryKeywords': encodeURI(keywordsSummaryOfPdf),
                                                            'title': encodeURI(pdfTitle),
                                                            'pages': encodeURI(pdfPagesCount)
                                                        });
                                                        res.send(content);
                                                        res.flush(); // for "compression" job gzip
                                                    }
                                                });
                                            } else if (err.code == 'ENOENT') {
                                                winstonLog.error('ENOENT');
                                                return next(err);
                                            } else {
                                                winstonLog.error('[PDF] Some other error: ', err.code);
                                                return next(err);
                                            }
                                        });

                                    });
                                    winstonLog.debug('[PDF] [parserPdf] XML to JSON convert Done');
                                });
                            });

                        });
                    });

                    // PDF READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS

                });
            });
        });


    }

    // PDFTOTEXT UTILITY

});
//              POST /PDF SERVICE


//              POST /LEMMA SERVICE
router.post('/lemma', lemmaApiLimiter, function (req, res, next) {

    if (!req.body) return res.sendStatus(400);
    winstonLog.info('[query for lemma] = [' + req.body.query + ']');
    var nameForNewQueryFile = 'query' + Date.now() + '.xml';

    fs.writeFile(__dirname + '/queryFiles/' + nameForNewQueryFile, req.body.query, function (err) {

        if (err) {
            winstonLog.error('[languageTool] [query writeFile]: ' + err);
            return next(err);
        }
        winstonLog.info('[languageTool] [nameForNewQueryFile] It\'s saved!');

        var childLemmaQuery = exec('env LC_ALL=uk_UA.UTF-8 java -jar ' + __dirname + '/languageTool/languagetool-commandline.jar --api -l uk -t ' + __dirname + '/queryFiles/' + nameForNewQueryFile, function (err, stdout) {

            if (err) {
                winstonLog.error('[languageTool] [childLemmaQuery]: ' + err);
                return next(err);
            }

            winstonLog.info('[languageTool output]: ' + stdout);

            res.type('Content-Type', 'application/xml');
            res.send(stdout);
            res.flush(); // for "compression" job gzip


            //delete tmp query file
            fs.unlink(__dirname + '/queryFiles/' + nameForNewQueryFile, function (err) {
                if (err) {
                    winstonLog.error('[languageTool] [nameForNewQueryFile]: ' + err);
                    return next(err);
                }
                winstonLog.info('successfully deleted nameForNewQueryFile');
            });

        });

        childLemmaQuery.on('exit', function (code) {
            winstonLog.info('Child process [languageTool] [childLemmaQuery] exited with exit code: ' + code);
        });

    });
});
//              POST /LEMMA SERVICE


//              POST /TXT SERVICE
router.post('/txt', upload, apiLimiter10RequestsEach25Seconds, function (req, res, next) {

    var pgrepTxt = exec('sh pgrep.sh', function (err, stdout, stderr) {

        if (err) {
            winstonLog.error(err);
            return next(err);
        }

    });

    pgrepTxt.stdout.on('data', function (summary) {

        if (summary.indexOf('wine') >= 0) {
            winstonLog.debug('[TXT] [PGREP] [503]: ' + summary);
            res.status(503).json({ status: 'Service is busy, try again later' });
        } else {

            winstonLog.debug('[TXT] req.file =  ' + req.file);
            winstonLog.debug('[TXT] filename = ' + req.file.filename);
            winstonLog.debug('[TXT] originalName = ' + req.file.originalname);
            winstonLog.debug('[TXT] path = ' + req.file.path);

            var stringForIndexTxt = req.file.originalname;
            var stringForKonspektTxt = req.file.originalname;


            if (stringForIndexTxt.indexOf(txtExtension) != -1) {

                winstonLog.debug('[TXT] extension of uploaded file = .txt');

                //Character encoding auto-detection in JavaScript (port of python's chardet)
                fs.readFile(req.file.path, function (err, data) {
                    if (err) {
                        winstonLog.error('[TXT] encoding auto-detection Internal error(%d): %s', res.statusCode, err);
                        fs.unlink(req.file.path);
                        return next(err)
                    }

                    var fileTXTEncoding = jsChardet.detect(data).encoding.toLowerCase();
                    winstonLog.debug(' [TXT] [Text encoding in accepted file] = ' + fileTXTEncoding);

                    if (fileTXTEncoding == 'windows-1251') {

                        var nameForPapersBinaryTxt = Date.now() + '_' + req.file.originalname;
                        nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';
                        ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {

                            if (err) {
                                winstonLog.error('[TXT] Internal error(%d): %s', res.statusCode, err);
                                return next(err);
                            }
                            winstonLog.debug('[TXT] Copy /rootconsole2016/ to /consoles done!');
                            winstonLog.debug('[TXT] Prepare to start Konspekt >> childConverterTXT');

//save papers originals
                            ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryTxt, function (err) {
                                if (err) {
                                    winstonLog.error('[TXT] Internal error(%d): %s', res.statusCode, err);
                                    return next(err);
                                }
                                winstonLog.info('[TXT] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryTxt);
                            });
//save papers originals

                            ncp(req.file.path, __dirname + nameForNewRecapDir + req.file.originalname, function (err) {
                                if (err) {
                                    winstonLog.error('[TXT] Internal error(%d): %s', res.statusCode, err);
                                    return next(err);
                                }

                                var childRecapTxt = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + stringForKonspektTxt, {
                                        timeout: 120000
                                    },
                                    function (err, stdout) {
                                        if (err) {
                                            winstonLog.error('[TXT] Internal error(%d): %s', res.statusCode, err);
                                            winstonLog.error(err.stack);
                                            winstonLog.error('[TXT] Error code: ' + err.code);
                                            winstonLog.error('[TXT] Signal received: ' + err.signal);
                                            return next(err);
                                        }

                                    });

                                childRecapTxt.on('exit', function (code) {
                                    if (code == 0) {
                                        winstonLog.debug('[TXT] Child process [childRecapTxt] exited with exit code ' + code);
                                        winstonLog.debug('[TXT] [childRecapTxt] done!');
                                        fs.stat(__dirname + nameForNewRecapDir + 'allterms.xml', function (err, stat) {
                                            if (err == null) {
                                                winstonLog.debug('[TXT] [allterms.xml] File exists');
                                                fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {
                                                    if (err) {
                                                        winstonLog.error('[TXT]: ' + err);
                                                        res.status(500).json({error: '[TXT]' + err});
                                                        fs.unlink(req.file.path);
                                                    } else {
                                                        winstonLog.info('[TXT]+[allterms.xml] It\'s read!');
                                                        //delete tmp file from uploads directory
                                                        fs.unlink(req.file.path);
                                                        winstonLog.debug('[TXT] tmp file deleted from uploads directory');
                                                        //delete tmp file from uploads directory
                                                        winstonLog.debug('[TXT] Sending xml to client!');
                                                        res.type('application/xml');
                                                        res.set({
                                                            'url': 'http://icybcluster.org.ua:33145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryTxt)
                                                        });

                                                        //Todo add unknown.txt and parce.xml files

                                                        fs.readFile(__dirname + nameForNewRecapDir + 'parce.xml', {encoding: "binary"}, function (err, f) {
                                                            if (err) {
                                                                winstonLog.error('[TXTJSON]: ' + err);
                                                                res.status(500).json({error: '[TXTJSON]' + err});
                                                                fs.unlink(req.file.path);
                                                            }

                                                            fs.readFile(__dirname + nameForNewRecapDir + 'unknown.txt', {encoding: "binary"}, function (err, u) {
                                                                if (err) {
                                                                    winstonLog.error('[TXTJSON]: ' + err);
                                                                    res.status(500).json({error: '[TXTJSON]' + err});
                                                                    fs.unlink(req.file.path);
                                                                }


                                                                res.send(data + os.EOL + f + os.EOL + u);
                                                                res.flush();

                                                            });

                                                        });

                                                    }
                                                });
                                            } else if (err.code == 'ENOENT') {
                                                winstonLog.error('[TXT] ENOENT');
                                                return next(err);
                                            } else {
                                                winstonLog.error('[TXT] Some other error: ', err.code);
                                                return next(err);
                                            }
                                        });
                                    } else {
                                        winstonLog.debug('[TXT] Child process [childRecapTxt] exited with exit code: ' + code);
                                        res.status(500).json({error: '[TXT] Error in Child process [childRecapTxt] execution. Exited with exit code: ' + code});
                                        fs.unlink(req.file.path);
                                    }
                                });
                            });
                        });
                    } else {
                        //WRONG FILE ENCODING
                        winstonLog.error('[TXT] Wrong file encoding! Uploaded file is ' + fileTXTEncoding + ', but must be in CP1251 encoding');
                        res.status(400).json({error: '[TXT] Wrong file encoding! Uploaded file is ' + fileTXTEncoding + ', but must be in CP1251 encoding'});
                        fs.unlink(req.file.path);
                        //WRONG FILE ENCODING
                    }
                });
                //Character encoding auto-detection in JavaScript (port of python's chardet)


            } else {
                //WRONG FILE FORMAT
                winstonLog.error('[TXT] Wrong file extension! Must be .txt in CP1251 encoding');
                res.status(400).json({error: '[TXT] Wrong file extension! Must be .txt in CP1251 encoding'});
                fs.unlink(req.file.path);
                //WRONG FILE FORMAT
            }
        }
    });
});
//               POST /TXT SERVICE

//              POST /PDFJSON SERVICE
router.post('/pdfJson', upload, apiLimiter10RequestsEach25Seconds, function (req, res, next) {

    var pgrepPdfJson = exec('sh pgrep.sh', function (err, stdout, stderr) {

        if (err) {
            winstonLog.error(err);
            return next(err);
        }

    });

    pgrepPdfJson.stdout.on('data', function (summary) {

        if (summary.indexOf('wine') >= 0) {
            winstonLog.debug('[utf8ToWin1251] [PGREP]: ' + summary);
            res.sendStatus(503);
        } else {

            var receiveHeadersPdfJson = req.headers;
            winstonLog.debug('[PDFJSON] inspect(receiveHeadersPdf) ' + inspect(receiveHeadersPdfJson));

            winstonLog.debug('[PDFJSON] req.file = ' + req.file);
            winstonLog.debug('[PDFJSON] filename = ' + req.file.filename);
            winstonLog.debug('[PDFJSON] originalName = ' + req.file.originalname);
            winstonLog.debug('[PDFJSON] path = ' + req.file.path);

            var stringForIndexPdf = req.file.originalname;


            if (stringForIndexPdf.indexOf(pdfExtension) == -1) {

                winstonLog.error('[PDFJSON] Wrong file extension! Must be .pdf');
                res.status(400).json({error: '[PDFJSON] Wrong file extension! Must be .pdf'});
                fs.unlink(req.file.path);

            } else {

                winstonLog.debug('[PDFJSON] extension of uploaded file = .pdf');

                var nameForPapersBinaryPdfJson = Date.now() + '_' + req.file.originalname;
                nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';

                ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {

                    if (err) {
                        winstonLog.error('[PDFJSON] Internal error(%d): %s', res.statusCode, err);
                        fs.unlink(req.file.path);
                        return next(err);
                    }

//save papers originals
                    ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryPdfJson, function (err) {
                        if (err) {
                            winstonLog.error('[PDFJSON] Internal error(%d): %s', res.statusCode, err);
                            fs.unlink(req.file.path);
                            return next(err);
                        }
                        winstonLog.info('[PDFJSON] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryPdfJson);

                    });
//save papers originals

                    ncp(req.file.path, __dirname + nameForNewRecapDir + req.file.originalname, function (err) {

                        if (err) {
                            winstonLog.error('[PDFJSON] Internal error(%d): %s', res.statusCode, err);
                            fs.unlink(req.file.path);
                            return next(err);
                        }


                        var childConverterPdfJson = exec("pdftotext -layout -nopgbrk -raw -eol unix " + '"' + __dirname + nameForNewRecapDir + req.file.originalname + '"' + ' ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {timeout: 120000},
                            function (err, stdout) {

                                if (err) {
                                    winstonLog.error('[PDFJSON] Internal error(%d): %s', err);
                                    winstonLog.error(err.stack);
                                    winstonLog.error('[PDFJSON] Error code: ' + err.code);
                                    winstonLog.error('[PDFJSON] Signal received: ' + err.signal);
                                    fs.unlink(req.file.path);
                                    return next(err);
                                }

                            });

                        childConverterPdfJson.on('exit', function (code) {

                            winstonLog.debug('[PDFJSON] Child process [childConverterPdf] exited with exit code ' + code);


                            // PDF READ/WRITE FILES ASYNC
                            fs.readFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdf.txt', {encoding: "UTF-8"}, function (err, data) {

                                if (err) {
                                    winstonLog.error('[PDFJSON] Internal error(%d): %s', res.statusCode, err);
                                    fs.unlink(req.file.path);
                                    return next(err);
                                }

                                winstonLog.info('[PDFJSON]+[fileForAnalysisPdf.txt] It\'s read!');


                                var outputFileTxtInCP1251 = iconv.encode(data, "win1251");

                                fs.writeFile(__dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', outputFileTxtInCP1251, function (err) {

                                    if (err) {
                                        winstonLog.error('[PDFJSON] Internal error(%d): %s', res.statusCode, err);
                                        fs.unlink(req.file.path);
                                        return next(err);
                                    }

                                    winstonLog.info('[PDFJSON]+[fileForAnalysisPdfCP1251.txt] It\'s saved!');

                                    var childRecapPdfJson = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + 'fileForAnalysisPdfCP1251.txt', {
                                            timeout: 120000,
                                            maxBuffer: 400 * 1024
                                        },
                                        function (err, stdout) {

                                            if (err) {
                                                winstonLog.error('[PDFJSON] Internal error(%d): %s', err);
                                                winstonLog.error(err.stack);
                                                winstonLog.error('[PDFJSON] Error code: ' + err.code);
                                                winstonLog.error('[PDFJSON] Signal received: ' + err.signal);
                                                fs.unlink(req.file.path);
                                                return next(err);
                                            }

                                        });

                                    childRecapPdfJson.on('exit', function (code) {

                                        winstonLog.debug('[PDFJSON] Child process [childRecapPdf] exited with exit code ' + code);
                                        winstonLog.debug('[PDFJSON] [childRecapPdf] done!');

                                        // PDF READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS
                                        fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {

                                            if (err) {
                                                winstonLog.error('[PDFJSON]+[allterms.xml]' + err);
                                                fs.unlink(req.file.path);
                                                return next(err);
                                            }
                                            winstonLog.info('[PDFJSON]+[allterms.xml] It\'s read!');

                                            var outputFileAlltermsInUtf8PdfJson = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

                                            fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInUtf8PdfJson, function (err) {

                                                if (err) {
                                                    winstonLog.debug('[PDFJSON]+alltermsUTF8.xml' + err);
                                                    fs.unlink(req.file.path);
                                                    return next(err);
                                                }

                                                winstonLog.info('[PDFJSON]+[alltermsUTF8.xml] It\'s saved!');

                                                var parserPdfJson = new xml2js.Parser({
                                                    strict: false,
                                                    explicitArray: true,
                                                    ignoreAttrs: true
                                                }); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.

                                                fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

                                                    if (err) {
                                                        winstonLog.error('[PDFJSON]+[alltermsUTF8.xml]' + err);
                                                        fs.unlink(req.file.path);
                                                        return next(err);
                                                    }

                                                    parserPdfJson.parseString(data, function (err, result) {

                                                        if (err) {
                                                            // something went wrong
                                                            winstonLog.error('[PDFJSON] [parserPdf]' + err);
                                                            fs.unlink(req.file.path);
                                                            return next(err);
                                                        }

                                                        winstonLog.info('[PDFJSON] xml2js.Parser {strict: false, explicitArray: true, ignoreAttrs: true}');

                                                        fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

                                                            if (err) {
                                                                // something went wrong, file probably not written.
                                                                winstonLog.error('[PDFJSON] ' + err);
                                                                fs.unlink(req.file.path);
                                                                return next(err);
                                                            }
                                                            fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
                                                                if (err == null) {
                                                                    winstonLog.debug('[PDFJSON]+[alltermsUTF8.json] File exists');
                                                                    fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
                                                                        if (error) {
                                                                            winstonLog.error(error);
                                                                            res.status(500).json({error: '[PDFJSON]' + error});
                                                                            fs.unlink(req.file.path);
                                                                        } else {
                                                                            //delete tmp file from uploads directory
                                                                            fs.unlink(req.file.path);
                                                                            winstonLog.debug('[PDFJSON] tmp file deleted from uploads directory');
                                                                            //delete tmp file from uploads directory
                                                                            winstonLog.debug('[PDFJSON] Sending json to client!');

                                                                            res.type('application/json');
                                                                            res.set({
                                                                                'url': 'http://icybcluster.org.ua:32145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryPdfJson)
                                                                            });

                                                                            fs.readFile(__dirname + nameForNewRecapDir + 'unknown.txt', function (err, f) {
                                                                                if (err) {
                                                                                    winstonLog.error('[TXTJSON]: ' + err);
                                                                                    res.status(500).json({error: '[TXTJSON]' + err});
                                                                                    fs.unlink(req.file.path);
                                                                                }
                                                                                var fInUtf8PdfJson = iconv.encode(iconv.decode(f, 'win1251'), 'utf8');
                                                                                var namesPdfJson = fInUtf8PdfJson.toString().split('\n');

                                                                                var unknownWordsArrayPdfJson = {unknownWordsArray: ["item1", "item2"]};

                                                                                for (var ln = 0; ln < namesPdfJson.length; ln++) {
                                                                                    unknownWordsArrayPdfJson.unknownWordsArray[ln] = namesPdfJson[ln];
                                                                                }
                                                                                var objPdfJson = JSON.parse(content);
                                                                                var sendContentPdfJson = extend(objPdfJson, unknownWordsArrayPdfJson);
                                                                                sendContentPdfJson = JSON.stringify(sendContentPdfJson);
                                                                                res.send(sendContentPdfJson);
                                                                                res.flush(); // for "compression" job gzip
                                                                            });
                                                                        }
                                                                    });
                                                                } else if (err.code == 'ENOENT') {
                                                                    fs.unlink(req.file.path);
                                                                    winstonLog.error('ENOENT');
                                                                    return next(err);
                                                                } else {
                                                                    winstonLog.error('[PDFJSON] Some other error: ', err.code);
                                                                    fs.unlink(req.file.path);
                                                                    return next(err);
                                                                }
                                                            });
                                                        });
                                                    });
                                                });

                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            }
        }
    });
});
//              POST /PDFJSON SERVICE

// utf8ToWin1251 for recap web app
router.post('/utf8ToWin1251', apiLimiter10RequestsEach5Seconds, function (req, res, next) {

    var pgrep = exec('sh pgrep.sh', function (err, stdout, stderr) {

        if (err) {
            winstonLog.error(err);
            return next(err);
        }

    });

    pgrep.stdout.on('data', function (summary) {

        if (summary.indexOf('wine') >= 0) {
            winstonLog.debug('[utf8ToWin1251] [PGREP]: ' + summary);
            res.sendStatus(503);
        } else {

            winstonLog.debug('[utf8ToWin1251] [PGREP]: ' + summary);

            if (!req.body) return res.sendStatus(400);

            var fileTXTJSONEncoding = jsChardet.detect(req.body.query).encoding.toLowerCase();
            winstonLog.debug(' [utf8ToWin1251] [Text encoding in accepted file] = ' + fileTXTJSONEncoding);

            var outputTableInUtf8 = iconv.encode(req.body.query, "win1251");

            var nameForNewQueryutf8ToWin1251File = 'tableForConfor' + Date.now() + '.csv';


            fs.writeFile(__dirname + '/queryFiles/forUtf8ToWin1251Query/' + nameForNewQueryutf8ToWin1251File, outputTableInUtf8, function (err) {

                if (err) {
                    // something went wrong, file probably not written.
                    winstonLog.error(err);
                    return next(err);
                }

                res.set({
                    'Content-Type': 'text/plain',
                    'url1': 'http://icybcluster.org.ua:32145/recapservice/api/Utf8ToWin1251/' + nameForNewQueryutf8ToWin1251File
                });

                //res.sendStatus(200);
                res.send('http://icybcluster.org.ua:32145/recapservice/api/Utf8ToWin1251/' + nameForNewQueryutf8ToWin1251File);
                res.flush();
            });
        }
    });
});
// utf8ToWin1251 for recap web app


//              POST /TXTJSON SERVICE
router.post('/txtjson', upload, apiLimiter10RequestsEach25Seconds, function (req, res, next) {


    var pgrepTxtJson = exec('sh pgrep.sh', function (err, stdout, stderr) {

        if (err) {
            winstonLog.error(err);
            return next(err);
        }

    });

    pgrepTxtJson.stdout.on('data', function (summary) {

        if (summary.indexOf('wine') >= 0) {
            winstonLog.debug('[utf8ToWin1251] [PGREP]: ' + summary);
            res.sendStatus(503);
        } else {

            winstonLog.debug('[TXTJSON] req.file = ' + req.file);
            winstonLog.debug('[TXTJSON] filename = ' + req.file.filename);
            winstonLog.debug('[TXTJSON] originalName = ' + req.file.originalname);
            winstonLog.debug('[TXTJSON] path = ' + req.file.path);

            var stringForIndexTxtJson = req.file.originalname;
            var stringForKonspektTxtJson = req.file.originalname;


            if (stringForIndexTxtJson.indexOf(txtExtension) != -1) {

                winstonLog.debug('[TXTJSON] extension of uploaded file = .txt');

                //Character encoding auto-detection in JavaScript (port of python's chardet)
                fs.readFile(req.file.path, function (err, data) {
                    if (err) {
                        winstonLog.error('[TXTJSON] encoding auto-detection Internal error(%d): %s', res.statusCode, err);
                        fs.unlink(req.file.path);
                        return next(err)
                    }

                    var fileTXTJSONEncoding = jsChardet.detect(data).encoding.toLowerCase();
                    winstonLog.debug(' [TXTJSON] [Text encoding in accepted file] = ' + fileTXTJSONEncoding);

                    if (fileTXTJSONEncoding == 'windows-1251') {

                        var nameForPapersBinaryTxtJson = Date.now() + '_' + req.file.originalname;
                        nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';
                        ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {

                            if (err) {
                                winstonLog.error('[TXTJSON] Internal error(%d): %s', res.statusCode, err);
                                fs.unlink(req.file.path);
                                return next(err);
                            }
                            winstonLog.debug('[TXTJSON] Copy /rootconsole2016/ to /consoles done!');
                            winstonLog.debug('[TXTJSON] Prepare to start Konspekt');

//save papers originals
                            ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryTxtJson, function (err) {
                                if (err) {
                                    winstonLog.error('Internal error(%d): %s', res.statusCode, err);
                                    fs.unlink(req.file.path);
                                    return next(err);
                                }
                                winstonLog.info('[TXTJSON] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryTxtJson);

                            });
//save papers originals

                            ncp(req.file.path, __dirname + nameForNewRecapDir + req.file.originalname, function (err) {
                                if (err) {
                                    winstonLog.error('[TXTJSON] Internal error(%d): %s', res.statusCode, err);
                                    fs.unlink(req.file.path);
                                    return next(err);
                                }


                                var childRecapTxtJson = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + stringForKonspektTxtJson, {
                                        timeout: 120000
                                    },
                                    function (err, stdout) {
                                        if (err) {
                                            winstonLog.error('[TXTJSON] Internal error(%d): %s', res.statusCode, err);
                                            winstonLog.error(err.stack);
                                            winstonLog.error('[TXTJSON] Error code: ' + err.code);
                                            winstonLog.error('[TXTJSON] Signal received: ' + err.signal);
                                            fs.unlink(req.file.path);
                                            return next(err);
                                        }

                                    });

                                childRecapTxtJson.on('exit', function (code) {
                                    if (code == 0) {
                                        winstonLog.debug('[TXTJSON] Child process [childRecapTxtJson] exited with exit code: ' + code);
                                        winstonLog.debug('[TXTJSON] [childRecapTxtJson] done!');
                                        // TXT READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS
                                        fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {

                                            if (err) {
                                                winstonLog.error('[TXTJSON]+[allterms.xml]' + err);
                                                fs.unlink(req.file.path);
                                                return next(err);
                                            }
                                            winstonLog.info('[TXTJSON]+[allterms.xml] It\'s read!');

                                            var outputFileAlltermsInTXTJSONUtf8 = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

                                            fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInTXTJSONUtf8, function (err) {

                                                if (err) {
                                                    winstonLog.error('[TXTJSON] [alltermsUTF8.xml]' + err);
                                                    fs.unlink(req.file.path);
                                                    return next(err);
                                                }

                                                winstonLog.info('[TXTJSON] [alltermsUTF8.xml] It\'s saved!');

                                                var parserTxtJson = new xml2js.Parser({
                                                    strict: false,
                                                    explicitArray: true,
                                                    ignoreAttrs: true
                                                }); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.

                                                fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

                                                    if (err) {
                                                        winstonLog.error('[TXTJSON]+[alltermsUTF8.xml]' + err);
                                                        fs.unlink(req.file.path);
                                                        return next(err);
                                                    }

                                                    parserTxtJson.parseString(data, function (err, result) {

                                                        if (err) {
                                                            // something went wrong
                                                            winstonLog.error('[TXTJSON] [parserTxtJson]' + err);
                                                            fs.unlink(req.file.path);
                                                            return next(err);
                                                        }

                                                        winstonLog.info('[TXTJSON] xml2js.Parser {strict: false, explicitArray: false, ignoreAttrs: true}');

                                                        //Write result json to log with eye
                                                        //winstonLog.debug(inspect(result));
                                                        //Write result json to log with eye

                                                        fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

                                                            if (err) {
                                                                // something went wrong, file probably not written.
                                                                winstonLog.error(err);
                                                                fs.unlink(req.file.path);
                                                                return next(err);
                                                            }

                                                            fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
                                                                if (err == null) {
                                                                    winstonLog.debug('[TXTJSON] [alltermsUTF8.json] File exists');
                                                                    fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
                                                                        if (error) {
                                                                            winstonLog.error('[TXTJSON]: ' + error);
                                                                            res.status(500).json({error: '[TXTJSON]' + error});
                                                                            fs.unlink(req.file.path);
                                                                        } else {
                                                                            //delete tmp file from uploads directory
                                                                            fs.unlink(req.file.path);
                                                                            winstonLog.debug('[TXTJSON] tmp file deleted from uploads directory');
                                                                            //delete tmp file from uploads directory
                                                                            winstonLog.debug('[TXTJSON] Sending json to client!');
                                                                            res.type('application/json');
                                                                            res.set({
                                                                                'url': 'http://icybcluster.org.ua:33145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryTxtJson)
                                                                            });


                                                                            fs.readFile(__dirname + nameForNewRecapDir + 'unknown.txt', function (err, f) {
                                                                                if (err) {
                                                                                    winstonLog.error('[TXTJSON]: ' + err);
                                                                                    res.status(500).json({error: '[TXTJSON]' + err});
                                                                                    fs.unlink(req.file.path);
                                                                                }

                                                                                var fInUtf8 = iconv.encode(iconv.decode(f, 'win1251'), 'utf8');
                                                                                var names = fInUtf8.toString().split('\n');

                                                                                var unknownWordsArray = {unknownWordsArray: ["item1", "item2"]};

                                                                                for (var ln = 0; ln < names.length; ln++) {
                                                                                    unknownWordsArray.unknownWordsArray[ln] = names[ln];
                                                                                }

                                                                                var obj = JSON.parse(content);
                                                                                var sendContent = extend(obj, unknownWordsArray);
                                                                                sendContent = JSON.stringify(sendContent);
                                                                                res.send(sendContent);
                                                                                res.flush();

                                                                            });
                                                                        }
                                                                    });
                                                                } else if (err.code == 'ENOENT') {
                                                                    winstonLog.error('[TXTJSON] ENOENT');
                                                                    fs.unlink(req.file.path);
                                                                    return next(err);
                                                                } else {
                                                                    winstonLog.error('[TXTJSON] Some other error: ', err.code);
                                                                    fs.unlink(req.file.path);
                                                                    return next(err);
                                                                }
                                                            });

                                                        });
                                                        winstonLog.debug('[TXTJSON] [parserTxtJson] XML to JSON convert Done');
                                                    });
                                                });
                                            });

                                        });
                                    } else {
                                        winstonLog.debug('[TXTJSON] Child process [childRecapTxtJson] exited with exit code: ' + code);
                                        res.status(500).json({error: '[TXTJSON] Error in Child process [childRecapTxtJson] execution. Exited with exit code: ' + code});
                                        fs.unlink(req.file.path);
                                    }
                                });


                                //If use this it will create window try error
                                /*
                                 childRecapTxtJson.stderr.on('data', function (stderrText) {
                                 winstonLog.debug('[TXTJSON] Error in [childRecapTxtJson] execution. Stderr output' + stderrText);
                                 res.status(500).json({ error: '[TXTJSON] Error in [childRecapTxtJson] execution. Stderr output' + stderrText});
                                 fs.unlink(req.file.path);
                                 });
                                 */
                            });
                        });
                    } else {
                        //WRONG FILE ENCODING
                        winstonLog.error('[TXTJSON] Wrong file encoding! Uploaded file is ' + fileTXTJSONEncoding + ', but must be in CP1251 encoding');
                        res.status(400).json({error: '[TXTJSON] Wrong file encoding! Uploaded file is ' + fileTXTJSONEncoding + ', but must be in CP1251 encoding'});
                        fs.unlink(req.file.path);
                        //WRONG FILE ENCODING
                    }

                });

            } else {
                //WRONG FILE FORMAT
                winstonLog.error('[TXTJSON] Wrong file extension! Must be .txt in CP1251 encoding');
                res.status(400).json({error: '[TXTJSON] Wrong file extension! Must be .txt in CP1251 encoding'});
                fs.unlink(req.file.path);
                //WRONG FILE FORMAT
            }
        }
    });
});
//              POST /TXTJSON SERVICE


//              POST /DOCDOCXJSON SERVICE
router.post('/docdocxJson', upload, apiLimiter10RequestsEach25Seconds, function (req, res, next) {

    var pgrepForDocDocxRequest = exec('sh pgrep.sh', function (err, stdout, stderr) {

        if (err) {
            winstonLog.error(err);
            return next(err);
        }

    });

    pgrepForDocDocxRequest.stdout.on('data', function (pgrepStatus) {

        if (pgrepStatus.indexOf('wine') >= 0) {
            winstonLog.debug('[DOC/DOCX] [PGREP]: ' + pgrepStatus);
            res.sendStatus(503);
        } else {

            winstonLog.debug(req.file);
            winstonLog.debug('[DOC/DOCX] filename = ' + req.file.filename);
            winstonLog.debug('[DOC/DOCX] originalName = ' + req.file.originalname);
            winstonLog.debug('[DOC/DOCX] path = ' + req.file.path);


            var stringForIndex = req.file.originalname;

            // DOCX2TXT UTILITY
            if (stringForIndex.indexOf(docxExtension) != -1) {

                winstonLog.debug('[DOCX] extension of uploaded file = .docx');

                var nameForPapersBinaryDocx = Date.now() + '_' + req.file.originalname;
                nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';
                ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {

                    if (err) {
                        winstonLog.error('[DOCX] Internal error(%d): %s', res.statusCode, err);
                        fs.unlink(req.file.path);
                        return next(err);
                    }

                    winstonLog.debug('[DOCX] Copy to /consoles done!');
                    winstonLog.debug('[DOCX] Prepare to start Konspekt >> childConverter');


//save papers originals
                    ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryDocx, function (err) {
                        if (err) {
                            winstonLog.error('[DOCX] Internal error(%d): %s', res.statusCode, err);
                            fs.unlink(req.file.path);
                            return next(err);
                        }
                        winstonLog.info('[DOCX] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryDocx);
                    });
//save papers originals


                    var childConverterDocx = exec("docx2txt < " + req.file.path + ' > ' + __dirname + nameForNewRecapDir + 'fileForAnalysisDocX.txt', {timeout: 180000},
                    //todo convert with https://github.com/ankushshah89/python-docx2txt
                    //var childConverterDocx = exec("python python-docx2txt/convertDocx2TxtScript.py " + req.file.path + ' ' + __dirname + nameForNewRecapDir + 'fileForAnalysisDocX.txt', {timeout: 180000},
                        function (err, stdout) {

                            if (err) {
                                winstonLog.error('[DOCX] Internal error(%d): %s', res.statusCode, err);
                                winstonLog.error(err.stack);
                                winstonLog.error('[DOCX] Error code: ' + err.code);
                                winstonLog.error('[DOCX] Signal received: ' + err.signal);
                                fs.unlink(req.file.path);
                                return next(err);
                            }

                        });

                    childConverterDocx.on('exit', function (code) {
                        if (code == 0) {
                            winstonLog.debug('[DOCX] childConverterDocx done!');
                            winstonLog.debug('[DOCX] Child process [childConverterDocx] exited with exit code ' + code);
                            // DOCX READ/WRITE FILES ASYNC+ ICONV-LITE
                            fs.readFile(__dirname + nameForNewRecapDir + 'fileForAnalysisDocX.txt', {encoding: "UTF-8"},
                                function (err, data) {
                                    if (err) {
                                        winstonLog.error('[DOCX]+[fileForAnalysisDocX.txt]' + err);
                                        fs.unlink(req.file.path);
                                        return next(err);
                                    }

                                    winstonLog.info('[DOCX]+[fileForAnalysisDocX.txt] It\'s read!');


                                    var outputFileInCP1251 = iconv.encode(data, "win1251");


                                    fs.writeFile(__dirname + nameForNewRecapDir + 'fileForAnalysisDocXCP1251.txt', outputFileInCP1251,
                                        function (err) {
                                            if (err) {
                                                winstonLog.error('[DOCX] [fileForAnalysisDocXCP1251.txt]' + err);
                                                fs.unlink(req.file.path);
                                                return next(err);
                                            }
                                            winstonLog.info('[DOCX]+[fileForAnalysisDocXCP1251.txt] It\'s saved!');

                                            var childRecapDocx = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + 'fileForAnalysisDocXCP1251.txt', {
                                                timeout: 120000
                                            }, function (err, stdout) {

                                                if (err) {
                                                    winstonLog.error('[DOCX] Internal error(%d): %s', res.statusCode, err);
                                                    winstonLog.error(err.stack);
                                                    winstonLog.error('[DOCX] Error code: ' + err.code);
                                                    winstonLog.error('[DOCX] Signal received: ' + err.signal);
                                                    fs.unlink(req.file.path);
                                                    return next(err);
                                                }

                                            });

                                            childRecapDocx.on('exit', function (code) {

                                                winstonLog.debug('[DOCX] Child process [childRecapDocx] exited with exit code ' + code);
                                                winstonLog.debug('[DOCX] [childRecapDocx] done!');

                                                // DOCX READ/WRITE FILES ASYNC + ICONV-LITE+ XML2JS
                                                fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {
                                                    if (err) {
                                                        winstonLog.error('[DOCX]+[allterms.xml] ' + err);
                                                        fs.unlink(req.file.path);
                                                        return next(err);
                                                    }

                                                    winstonLog.info('[DOCX]+[allterms.xml] It\'s read!');

                                                    var outputFileAlltermsInUtf8Docx = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

                                                    fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInUtf8Docx, function (err) {
                                                        if (err) {
                                                            winstonLog.error('[DOCX] [alltermsUTF8.xml]' + err);
                                                            fs.unlink(req.file.path);
                                                            return next(err);
                                                        }

                                                        winstonLog.info('[DOCX] [alltermsUTF8.xml] It\'s saved!');

                                                        var parserDocx = new xml2js.Parser({
                                                            strict: false,
                                                            explicitArray: true,
                                                            ignoreAttrs: true
                                                        }); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.

                                                        fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

                                                            if (err) {
                                                                winstonLog.error('[DOCX]+[alltermsUTF8.xml]' + err);
                                                                fs.unlink(req.file.path);
                                                                return next(err);
                                                            }

                                                            parserDocx.parseString(data, function (err, result) {

                                                                if (err) {
                                                                    winstonLog.error('[DOCX] [parserDocx]' + err);
                                                                    fs.unlink(req.file.path);
                                                                    return next(err);
                                                                }

                                                                winstonLog.info('[DOCX] xml2js.Parser {strict: false, explicitArray: false, ignoreAttrs: true}');
                                                                fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

                                                                    if (err) {
                                                                        winstonLog.error(err);
                                                                        fs.unlink(req.file.path);
                                                                        return next(err);
                                                                    }

                                                                    fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
                                                                        if (err == null) {
                                                                            winstonLog.debug('[DOCX] [alltermsUTF8.json] File exists');
                                                                            fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
                                                                                if (error) {
                                                                                    winstonLog.error(error);
                                                                                    fs.unlink(req.file.path);
                                                                                    winstonLog.error('[DOCX]: ' + error);
                                                                                    res.status(500).json({error: '[DOCX]' + error});
                                                                                } else {
                                                                                    fs.unlink(req.file.path);
                                                                                    winstonLog.debug('[DOCX] Sending json to client!');
                                                                                    res.type('application/json');
                                                                                    res.set({
                                                                                        'url': 'http://icybcluster.org.ua:33145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryDocx)
                                                                                    });
                                                                                    fs.readFile(__dirname + nameForNewRecapDir + 'unknown.txt', function (err, f) {
                                                                                        if (err) {
                                                                                            winstonLog.error('[DOCX]: ' + err);
                                                                                            res.status(500).json({error: '[DOCX]' + err});
                                                                                            fs.unlink(req.file.path);
                                                                                        }
                                                                                        var fInUtf8 = iconv.encode(iconv.decode(f, 'win1251'), 'utf8');
                                                                                        var names = fInUtf8.toString().split('\n');

                                                                                        var unknownWordsArrayForDocx = {unknownWordsArray: ["item1", "item2"]};

                                                                                        for (var ln = 0; ln < names.length; ln++) {
                                                                                            unknownWordsArrayForDocx.unknownWordsArray[ln] = names[ln];
                                                                                        }
                                                                                        var obj = JSON.parse(content);
                                                                                        var sendContentForDocx = extend(obj, unknownWordsArrayForDocx);
                                                                                        sendContentForDocx = JSON.stringify(sendContentForDocx);
                                                                                        res.send(sendContentForDocx);
                                                                                        res.flush();
                                                                                    });

                                                                                }
                                                                            });
                                                                        } else if (err.code == 'ENOENT') {
                                                                            winstonLog.error('ENOENT');
                                                                            fs.unlink(req.file.path);
                                                                            return next(err);
                                                                        } else {
                                                                            winstonLog.error('[DOCX] Some other error: ', err.code);
                                                                            fs.unlink(req.file.path);
                                                                            return next(err);
                                                                        }
                                                                    });

                                                                });
                                                                winstonLog.debug('[DOCX] [parserDocx] XML to JSON convert done!');
                                                            });
                                                        });

                                                    });
                                                });
                                                // DOCX READ/WRITE FILES ASYNC + ICONV-LITE+ XML2JS
                                            });

                                        });
                                });
                            // DOCX READ/WRITE FILES ASYNC+ ICONV-LITE


                        } else {
                            winstonLog.debug('[DOCX] Child process [childConverterDocx] exited with exit code: ' + code);
                            fs.unlink(req.file.path);
                            res.status(500).json({error: '[DOCX] Error in Child process [childConverterDocx] execution. Exited with exit code: ' + code});
                        }
                    });

                });


            }
            // DOCX2TXT UTILITY

            else {


                //CATDOC UTILITY

                if (stringForIndex.indexOf(docExtension) != -1) {

                    winstonLog.debug('[DOC] extension of uploaded file = .doc');

                    var nameForPapersBinaryDoc = Date.now() + '_' + req.file.originalname;
                    nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';
                    ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {
                        if (err) {
                            winstonLog.error('[DOC] Internal error(%d): %s', res.statusCode, err);
                            fs.unlink(req.file.path);
                            return next(err);
                        }

                        winstonLog.debug('[DOC] Copy to /consoles done!');
                        winstonLog.debug('[DOC] Prepare to start Konspekt >> childConverter');

//save papers originals
                        ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryDoc, function (err) {
                            if (err) {
                                winstonLog.error('[DOC] Internal error(%d): %s', res.statusCode, err);
                                fs.unlink(req.file.path);
                                return next(err);
                            }
                            winstonLog.info('[DOC] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryDoc);

                        });
//save papers originals

                        var childConverterDoc = exec("catdoc -d cp1251 " + req.file.path + ' >' + __dirname + nameForNewRecapDir + 'fileForAnalysis.txt', {timeout: 180000},
                            function (err, stdout) {

                                if (err) {
                                    winstonLog.error('[DOC] Internal error(%d): %s', res.statusCode, err);
                                    winstonLog.error(err.stack);
                                    winstonLog.error('[DOC] Error code: ' + err.code);
                                    winstonLog.error('[DOC] Signal received: ' + err.signal);
                                    fs.unlink(req.file.path);
                                    return next(err);
                                }
                            });

                        childConverterDoc.on('exit', function (code) {

                            if (code == 0) {
                                winstonLog.debug('[DOC] Child process [childConverterDoc] exited with exit code ' + code);
                                winstonLog.debug('[DOC] childConverterDoc done!');

                                var childRecapDoc = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + 'fileForAnalysis.txt', {
                                    timeout: 120000
                                }, function (err, stdout) {

                                    if (err) {
                                        winstonLog.error('[DOC] Internal error(%d): %s', res.statusCode, err);
                                        winstonLog.error(err.stack);
                                        winstonLog.error('[DOC] Error code: ' + err.code);
                                        winstonLog.error('[DOC] Signal received: ' + err.signal);
                                        fs.unlink(req.file.path);
                                        return next(err);
                                    }
                                });

                                childRecapDoc.on('exit', function (code) {
                                    winstonLog.debug('[DOC] Child process [childRecapDoc] exited with exit code ' + code);
                                    if (code == 0) {
                                        // DOC READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS
                                        fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {
                                            if (err) {
                                                winstonLog.error('[DOC]+[allterms.xml]' + err);
                                                fs.unlink(req.file.path);
                                                return next(err);
                                            }
                                            winstonLog.info('[DOC]+[allterms.xml] It\'s read!');

                                            var outputFileAlltermsInUtf8Doc = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

                                            fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInUtf8Doc, function (err) {
                                                if (err) {
                                                    winstonLog.error('[DOC] [alltermsUTF8.xml]' + err);
                                                    fs.unlink(req.file.path);
                                                    return next(err);
                                                }
                                                winstonLog.info('[DOC] [alltermsUTF8.xml] It\'s saved!');


                                                var parserDoc = new xml2js.Parser({//TODO apostrophe in xml ===> " &quot; '   &apos; <   &lt; >   &gt; &   &amp;
                                                    strict: false,
                                                    explicitArray: true,
                                                    ignoreAttrs: true
                                                }); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.
                                                fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

                                                    if (err) {
                                                        winstonLog.error('[DOC]+[alltermsUTF8.xml] ' + err);
                                                        fs.unlink(req.file.path);
                                                        return next(err);
                                                    }

                                                    parserDoc.parseString(data, function (err, result) {

                                                        if (err) {
                                                            // something went wrong
                                                            winstonLog.error('[DOC] [parserDoc] ' + err);
                                                            fs.unlink(req.file.path);
                                                            return next(err);
                                                        }

                                                        winstonLog.info('[DOC] xml2js.Parser {strict: false, explicitArray: false, ignoreAttrs: true}');
                                                        fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

                                                            if (err) {
                                                                // something went wrong, file probably not written.
                                                                fs.unlink(req.file.path);
                                                                winstonLog.error(err);
                                                                return next(err);
                                                            }

                                                            fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
                                                                if (err == null) {
                                                                    winstonLog.debug('[DOC] [alltermsUTF8.json] File exists');
                                                                    fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
                                                                        if (error) {
                                                                            winstonLog.error(error);
                                                                            fs.unlink(req.file.path);
                                                                            winstonLog.error('[DOC]: ' + error);
                                                                            res.status(500).json({error: error});
                                                                        } else {
                                                                            fs.unlink(req.file.path);
                                                                            winstonLog.debug('[DOC] Sending json to client!');
                                                                            res.type('application/json');
                                                                            res.set({
                                                                                'url': 'http://icybcluster.org.ua:33145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryDoc)
                                                                            });

                                                                            fs.readFile(__dirname + nameForNewRecapDir + 'unknown.txt', function (err, f) {
                                                                                if (err) {
                                                                                    winstonLog.error('[DOC]: ' + err);
                                                                                    res.status(500).json({error: '[DOC]' + err});
                                                                                    fs.unlink(req.file.path);
                                                                                }
                                                                                var fInUtf8 = iconv.encode(iconv.decode(f, 'win1251'), 'utf8');
                                                                                var names = fInUtf8.toString().split('\n');

                                                                                var unknownWordsArrayForDoc = {unknownWordsArray: ["item1", "item2"]};

                                                                                for (var ln = 0; ln < names.length; ln++) {
                                                                                    unknownWordsArrayForDoc.unknownWordsArray[ln] = names[ln];
                                                                                }
                                                                                var obj = JSON.parse(content);
                                                                                var sendContentForDoc = extend(obj, unknownWordsArrayForDoc);
                                                                                sendContentForDoc = JSON.stringify(sendContentForDoc);
                                                                                res.send(sendContentForDoc);
                                                                                res.flush();
                                                                            });

                                                                        }
                                                                    });
                                                                } else if (err.code == 'ENOENT') {
                                                                    fs.unlink(req.file.path);
                                                                    winstonLog.error('ENOENT');
                                                                    return next(err);
                                                                } else {
                                                                    winstonLog.error('[DOC] Some other error: ', err.code);
                                                                    fs.unlink(req.file.path);
                                                                    return next(err);
                                                                }
                                                            });

                                                        });
                                                        winstonLog.debug('[DOC] [parserDoc] XML to JSON convert Done');
                                                    });
                                                });
                                            });
                                        });
                                    } else {
                                        winstonLog.debug('[DOC] Child process [childRecapDoc] exited with exit code: ' + code);
                                        res.status(500).json({error: '[DOC] Error in Child process [childRecapDoc] execution. Exited with exit code: ' + code});
                                        fs.unlink(req.file.path);
                                    }
                                });

                            } else {
                                winstonLog.debug('[DOC] Child process [childConverterDoc] exited with exit code: ' + code);
                                res.status(500).json({error: '[DOC] Error in Child process [childConverterDoc] execution. Exited with exit code: ' + code});
                                fs.unlink(req.file.path);
                            }
                        });
                    });


                    //CATDOC UTILITY


                } else {
                    //WRONG FILE FORMAT
                    fs.unlink(req.file.path);
                    winstonLog.error('[DOC/DOCX] Wrong file extension! Must be .doc/.docx');
                    res.status(400).json({error: '[DOC/DOCX] Wrong file extension! Must be .doc/.docx'});
                    //WRONG FILE FORMAT
                }

            }

        }
    });
});
/*router.post('/docdocx', upload, apiLimiter10RequestsEach25Seconds, function (req, res, next) {

 var pgrepForDocDocxRequest = exec('sh pgrep.sh', function (err, stdout, stderr) {

 if (err) {
 winstonLog.error(err);
 return next(err);
 }

 });

 pgrepForDocDocxRequest.stdout.on('data', function (pgrepStatus) {

 if (pgrepStatus.indexOf('wine') >= 0) {
 winstonLog.debug('[utf8ToWin1251] [PGREP]: ' + pgrepStatus);
 res.sendStatus(503);
 } else {

 winstonLog.debug(req.file);
 winstonLog.debug('filename = ' + req.file.filename);
 winstonLog.debug('originalName = ' + req.file.originalname);
 winstonLog.debug('path = ' + req.file.path);


 var stringForIndex = req.file.originalname;

 // DOCX2TXT UTILITY

 if (stringForIndex.indexOf(docxExtension) != -1) {

 winstonLog.debug('extension of uploaded file = .docx');

 var nameForPapersBinaryDocx = Date.now() + '_' + req.file.originalname;
 nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';
 ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }

 winstonLog.debug('Copy to /consoles done!');
 winstonLog.debug('Prepare to start Konspekt >> childConverter');


 //save papers originals
 ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryDocx, function (err) {
 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }
 winstonLog.info('[DOCX] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryDocx);

 });
 //save papers originals


 var childConverterDocx = exec("docx2txt < " + req.file.path + ' > ' + __dirname + nameForNewRecapDir + 'fileForAnalysisDocX.txt', {timeout: 180000},
 function (err, stdout) {

 if (err) {
 winstonLog.error('[DOCX] Internal error(%d): %s', res.statusCode, err);
 winstonLog.error(err.stack);
 winstonLog.error('[DOCX] Error code: ' + err.code);
 winstonLog.error('[DOCX] Signal received: ' + err.signal);
 return next(err);
 }

 winstonLog.debug('[DOCX] childConverterDocx done!');
 winstonLog.debug(stdout);

 // DOCX READ/WRITE FILES ASYNC+ ICONV-LITE
 fs.readFile(__dirname + nameForNewRecapDir + 'fileForAnalysisDocX.txt', {encoding: "UTF-8"},
 function (err, data) {
 if (err) {
 winstonLog.error('[DOCX]+[fileForAnalysisDocX.txt]' + err);
 return next(err);
 }
 winstonLog.info('[DOCX]+[fileForAnalysisDocX.txt] It\'s read!');


 var outputFileInCP1251 = iconv.encode(data, "win1251");


 fs.writeFile(__dirname + nameForNewRecapDir + 'fileForAnalysisDocXCP1251.txt', outputFileInCP1251,
 function (err) {
 if (err) {
 winstonLog.error('[DOCX] [fileForAnalysisDocXCP1251.txt]' + err);
 return next(err);
 }
 winstonLog.info('[DOCX]+[fileForAnalysisDocXCP1251.txt] It\'s saved!');
 });

 });
 // DOCX READ/WRITE FILES ASYNC+ ICONV-LITE
 });

 childConverterDocx.on('exit', function (code) {
 winstonLog.debug('Child process [childConverterDocx] exited with exit code ' + code);
 });


 var childRecapDocx = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + 'fileForAnalysisDocXCP1251.txt', {
 timeout: 120000 }, function (err, stdout) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 winstonLog.error(err.stack);
 winstonLog.error('Error code: ' + err.code);
 winstonLog.error('Signal received: ' + err.signal);
 return next(err);
 }

 winstonLog.debug('childRecapDocx done!');
 winstonLog.debug(stdout);


 // DOCX READ/WRITE FILES ASYNC + ICONV-LITE+ XML2JS
 fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {
 if (err) {
 winstonLog.error('[DOCX]+[allterms.xml]' + err);
 return next(err);
 }

 winstonLog.info('[DOCX]+[allterms.xml] It\'s read!');

 var outputFileAlltermsInUtf8Docx = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

 fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInUtf8Docx, function (err) {
 if (err) {
 winstonLog.error('[DOCX] [alltermsUTF8.xml]' + err);
 return next(err);
 }

 winstonLog.info('[DOCX] [alltermsUTF8.xml] It\'s saved!');

 });


 var parserDocx = new xml2js.Parser({strict: false, explicitArray: true, ignoreAttrs: true}); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.

 fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

 if (err) {
 winstonLog.error('[DOCX]+[alltermsUTF8.xml]' + err);
 return next(err);
 }

 parserDocx.parseString(data, function (err, result) {

 if (err) {
 // something went wrong
 winstonLog.error('[parserDocx]' + err);
 return next(err);
 }

 winstonLog.info('[DOCX] xml2js.Parser {strict: false, explicitArray: false, ignoreAttrs: true}');
 winstonLog.debug(inspect(result));
 fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

 if (err) {
 // something went wrong, file probably not written.
 winstonLog.error(err);
 return next(err);
 }

 fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
 if (err == null) {
 winstonLog.debug('File exists');
 fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
 if (error) {
 winstonLog.error(error);
 res.writeHead(500);
 res.end();
 }
 else {
 fs.unlink(req.file.path);
 winstonLog.debug('tmp file deleted from uploads directory');

 winstonLog.debug('Sending file');
 res.type('application/json');
 res.set({
 'url': 'http://icybcluster.org.ua:33145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryDocx)
 });
 res.send(content);
 res.flush();
 }
 });
 } else if (err.code == 'ENOENT') {
 winstonLog.error('ENOENT');
 return next(err);
 } else {
 winstonLog.error('Some other error: ', err.code);
 return next(err);
 }
 });

 });
 winstonLog.debug('[parserDocx] XML to JSON convert done!');
 });
 });
 });
 // DOCX READ/WRITE FILES ASYNC + ICONV-LITE+ XML2JS
 });

 childRecapDocx.on('exit', function (code) {
 winstonLog.debug('Child process [childRecapDocx] exited with exit code ' + code);
 });

 });


 } else {


 //CATDOC UTILITY

 if (stringForIndex.indexOf(docExtension) != -1) {

 winstonLog.debug('extension of uploaded file = .doc');

 var nameForPapersBinaryDoc = Date.now() + '_' + req.file.originalname;
 nameForNewRecapDir = '/consoles/console_' + Date.now() + '/';
 ncp(__dirname + '/rootconsole2016/', __dirname + nameForNewRecapDir, function (err) {
 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }

 winstonLog.debug('Copy to /consoles done!');
 winstonLog.debug('Prepare to start Konspekt >> childConverter');

 //save papers originals
 ncp(req.file.path, __dirname + '/papersBinary/' + nameForPapersBinaryDoc, function (err) {
 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 return next(err);
 }
 winstonLog.info('[DOC] binary originals saved! [PATH]:' + __dirname + '/papersBinary/' + nameForPapersBinaryDoc);

 });
 //save papers originals

 var childConverterDoc = exec("catdoc -d cp1251 " + req.file.path + ' >' + __dirname + nameForNewRecapDir + 'fileForAnalysis.txt', {timeout: 180000},
 function (err, stdout) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 winstonLog.error(err.stack);
 winstonLog.error('Error code: ' + err.code);
 winstonLog.error('Signal received: ' + err.signal);
 return next(err);
 }

 winstonLog.debug(stdout);
 winstonLog.debug('childConverterDoc done!');
 //fs.unlink(req.file.path);

 });

 childConverterDoc.on('exit', function (code) {
 winstonLog.debug('Child process [childConverterDoc] exited with exit code ' + code);
 });

 var childRecapDoc = exec('env LC_ALL=ru_RU.CP1251 wine ' + __dirname + nameForNewRecapDir + 'Konspekt.exe ' + __dirname + nameForNewRecapDir + 'fileForAnalysis.txt', {
 timeout: 120000 }, function (err, stdout) {

 if (err) {
 winstonLog.error('Internal error(%d): %s', res.statusCode, err);
 winstonLog.error(err.stack);
 winstonLog.error('Error code: ' + err.code);
 winstonLog.error('Signal received: ' + err.signal);
 return next(err);
 }

 winstonLog.debug('childRecapDoc done');
 winstonLog.debug(stdout);


 // DOC READ/WRITE FILES ASYNC + ICONV-LITE + XML2JS
 fs.readFile(__dirname + nameForNewRecapDir + 'allterms.xml', {encoding: "binary"}, function (err, data) {
 if (err) {
 winstonLog.error('[DOC]+[allterms.xml]' + err);
 return next(err);
 }
 winstonLog.info('[DOC]+[allterms.xml] It\'s read!');

 var outputFileAlltermsInUtf8Doc = iconv.encode(iconv.decode(data, 'win1251'), 'utf8');

 fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', outputFileAlltermsInUtf8Doc, function (err) {
 if (err) {
 winstonLog.error('[DOC] [alltermsUTF8.xml]' + err);
 return next(err);
 }
 winstonLog.info('[DOC] [alltermsUTF8.xml] It\'s saved!');


 var parserDoc = new xml2js.Parser({
 strict: false,
 explicitArray: true,
 ignoreAttrs: true
 }); // strict (default true): Set sax-js to strict or non-strict parsing mode. Defaults to true which is highly recommended, since parsing HTML which is not well-formed XML might yield just about anything. Added in 0.2.7.
 fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.xml', function (err, data) {

 if (err) {
 winstonLog.error('[DOC]+[alltermsUTF8.xml]' + err);
 return next(err);
 }

 parserDoc.parseString(data, function (err, result) {

 if (err) {
 // something went wrong
 winstonLog.error('[parserDoc]' + err);
 return next(err);
 }

 winstonLog.info('xml2js.Parser {strict: false, explicitArray: false, ignoreAttrs: true}');
 winstonLog.debug(inspect(result));
 fs.writeFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', JSON.stringify(result, null, '\t'), function (err) {

 if (err) {
 // something went wrong, file probably not written.
 winstonLog.error(err);
 return next(err);
 }

 fs.stat(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (err, stat) {
 if (err == null) {
 winstonLog.debug('File exists');
 fs.readFile(__dirname + nameForNewRecapDir + 'alltermsUTF8.json', function (error, content) {
 if (error) {
 winstonLog.error(error);
 res.writeHead(500);
 res.end();
 }
 else {
 fs.unlink(req.file.path);
 winstonLog.debug('tmp file deleted from uploads directory');
 winstonLog.debug('Sending file');
 res.type('application/json');
 res.set({
 'url': 'http://icybcluster.org.ua:33145/recapservice/api/binary/' + encodeURI(nameForPapersBinaryDoc)
 });
 res.send(content);
 }
 });
 } else if (err.code == 'ENOENT') {
 winstonLog.error('ENOENT');
 return next(err);
 } else {
 winstonLog.error('Some other error: ', err.code);
 return next(err);
 }
 });

 });
 winstonLog.debug('[parserDoc] XML to JSON convert Done');
 });
 });
 });
 });
 });

 childRecapDoc.on('exit', function (code) {
 winstonLog.debug('Child process [childRecapDoc] exited with exit code ' + code);
 });

 });


 //CATDOC UTILITY


 } else {

 //WRONG FILE FORMAT

 res.writeHead(200, {'Content-Type': 'text/plain'});
 winstonLog.debug('Wrong file extension! Must be .doc or .docx');
 res.end('Wrong file extension! Must be .doc or .docx');
 fs.unlink(req.file.path);

 //WRONG FILE FORMAT


 }

 }

 }
 });
 });*/
//              POST /DOCDOCXJSON SERVICE


//              POST /SCHOLAR SERVICE
router.post('/scholar', scholarApiLimiter, function (req, res, next) {

    if (!req.body) return res.sendStatus(400);
    winstonLog.info('[query for scholar author accepted] = [' + req.body.author + ']');
    winstonLog.info('[query for scholar phrase accepted] = [' + req.body.phrase + ']');

    var childScholarQuery = exec('env LC_ALL=uk_UA.UTF-8 python ' + __dirname + '/scholarPy/scholar.py -c 10 --author "' + req.body.author + '" --phrase "' + req.body.phrase + '"', function (err, stdout) {

        if (err) {
            winstonLog.error('[scholar.py] [childScholarQuery]: ' + err);
            return next(err);
        }

        winstonLog.info('[scholar.py output]: ' + stdout);

        res.send(stdout);

    });

    childScholarQuery.on('exit', function (code) {
        winstonLog.info('Child process [scholar.py] [childScholarQuery] exited with exit code: ' + code);
    });
});
//              POST /SCHOLAR SERVICE


//              POST /SCHOLARCSV SERVICE
router.post('/scholarcsv', scholarApiLimiter, function (req, res, next) {

    if (!req.body) return res.sendStatus(400);
    winstonLog.info('[query for scholarCSV author accepted] = [' + req.body.author + ']');
    winstonLog.info('[query for scholarCSV phrase accepted] = [' + req.body.phrase + ']');

    var childScholarQuery = exec('env LC_ALL=uk_UA.UTF-8 python ' + __dirname + '/scholarPy/scholar.py -c 10 --author "' + req.body.author + '" --phrase "' + req.body.phrase + '" --no-patents --csv-header', function (err, stdout) {

        if (err) {
            winstonLog.error('[scholar.py] [childScholarCSVQuery]: ' + err);
            return next(err);
        }

        winstonLog.info('[scholar.py CSV output]: ' + stdout);

        res.send(stdout);
        res.flush();

    });

    childScholarQuery.on('exit', function (code) {
        winstonLog.info('Child process [scholar.py] [childScholarCSVQuery] exited with exit code: ' + code);
    });
});
//              POST /SCHOLARCSV SERVICE


//              POST /TCONSPECTUS
/*router.post('/tconspectus', apiLimiter, function (req, res, next) {

    winstonLog.debug(req.body.text);


    var text = req.body.text;
    var textForResponse;

    var options = {
        method: 'POST',
        url: 'http://tconspectus.pythonanywhere.com/summarization',
        gzip: true,
        headers: {
            'postman-token': 'ca0acbe7-fed7-827a-b288-0a55dfa4f34f',
            'accept-language': 'en-US,ru;q=0.8,uk;q=0.6,en;q=0.4,hy;q=0.2',
            'accept-encoding': 'gzip, deflate',
            referer: 'http://tconspectus.pythonanywhere.com/summarization',
            dnt: '1',
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*!/!*;q=0.8',
            'content-type': 'multipart/form-data; boundary=----WebKitFormBoundaryWbmEnC9zjSt5NPE2',
            'upgrade-insecure-requests': '1',
            origin: 'http://tconspectus.pythonanywhere.com',
            'cache-control': 'no-cache',
            connection: 'keep-alive',
            host: 'tconspectus.pythonanywhere.com'
        },
        body: '------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="mytext"\r\n\r\n' +
        text + '\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="action"\r\n\r\nsummarize\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="url_fieled"\r\n\r\n\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="upfile"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="action"\r\n\r\nupload\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="sumsize"\r\n\r\n15\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="keywords"\r\n\r\non\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="kwis"\r\n\r\non\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2--'
    };


    request(options, function (error, response, body) {
        if (error) throw new Error(error);

        winstonLog.debug(body);
        textForResponse = body;
        res.set({
            'Access-Control-Allow-Origin': '*'
        });
        res.type('.html');
        res.send(textForResponse);

    });

});*/
//              POST /TCONSPECTUS


//              OTS FUNCTIONS
function otsForUaTextsWithSimpleOutput(fileForSummarize, extractedSummaryCallback) {

    var childOpenTextSummarizer = exec('ots -r 15 --dic uk ' + fileForSummarize, function (err, stdout, stderr) {

        if (err) {
            winstonLog.error('[childOpenTextSummarizer] Error code: ' + err.code);
            winstonLog.error('[childOpenTextSummarizer] Signal received: ' + err.signal);
            return winstonLog.error(err.stack);
        }
        winstonLog.debug('[childOpenTextSummarizer]:' + '\n' + stdout);
        extractedSummaryCallback(stdout);
    });

    childOpenTextSummarizer.on('exit', function (code) {
        winstonLog.debug('[childOpenTextSummarizer]: Child process [childOpenTextSummarizer] exited with exit code ' + code);
    });

    childOpenTextSummarizer.stdout.on('data', function (summary) {

    });
    childOpenTextSummarizer.stderr.on('data', function (summaryError) {
        extractedSummaryCallback('[childOpenTextSummarizer] stderr: ' + summaryError);
    });

}

function otsForUaTextsWithHtmlOutput(fileForSummarizeWithHtml, extractedSummaryWithHtmlCallback) {

    var childOpenTextSummarizerWithHtmlOutput = exec('ots -h -r 15 --dic uk ' + fileForSummarizeWithHtml, function (err, stdout, stderr) {

        if (err) {
            winstonLog.error('[childOpenTextSummarizerWithHtmlOutput] Error code: ' + err.code);
            winstonLog.error('[childOpenTextSummarizerWithHtmlOutput] Signal received: ' + err.signal);
            return winstonLog.error(err.stack);
        }
        winstonLog.debug('[childOpenTextSummarizerWithHtmlOutput]:' + '\n' + stdout);
        extractedSummaryWithHtmlCallback(stdout);
    });

    childOpenTextSummarizerWithHtmlOutput.on('exit', function (code) {
        winstonLog.debug('[childOpenTextSummarizerWithHtmlOutput]: Child process [childOpenTextSummarizerWithHtmlOutput] exited with exit code ' + code);
    });

    childOpenTextSummarizerWithHtmlOutput.stdout.on('data', function (summaryWithHtmlOutput) {

    });
    childOpenTextSummarizerWithHtmlOutput.stderr.on('data', function (summaryWithHtmlOutputError) {
        extractedSummaryWithHtmlCallback('[childOpenTextSummarizerWithHtmlOutput] stderr: ' + summaryWithHtmlOutputError);
    });

}

function otsForUaTextsWithKeywordsOutput(fileForSummarizeWithKeywords, extractedSummaryWithKeywordsCallback) {

    var childOpenTextSummarizerWithKeywordsOutput = exec('ots --about --dic uk ' + fileForSummarizeWithKeywords, function (err, stdout, stderr) {

        if (err) {
            winstonLog.error('[childOpenTextSummarizerWithKeywordsOutput] Error code: ' + err.code);
            winstonLog.error('[childOpenTextSummarizerWithKeywordsOutput] Signal received: ' + err.signal);
            return winstonLog.error(err.stack);
        }
        winstonLog.debug('[childOpenTextSummarizerWithKeywordsOutput]:' + '\n' + stdout);
        extractedSummaryWithKeywordsCallback(stdout);
    });

    childOpenTextSummarizerWithKeywordsOutput.on('exit', function (code) {
        winstonLog.debug('[childOpenTextSummarizerWithKeywordsOutput]: Child process [childOpenTextSummarizerWithKeywordsOutput] exited with exit code ' + code);
    });

    childOpenTextSummarizerWithKeywordsOutput.stdout.on('data', function (summaryWithKeywordOutput) {

    });
    childOpenTextSummarizerWithKeywordsOutput.stderr.on('data', function (summaryWithKeywordsOutputError) {
        extractedSummaryWithKeywordsCallback('[childOpenTextSummarizerWithKeywordsOutput] stderr: ' + summaryWithKeywordsOutputError);
    });

}
//              OTS FUNCTIONS

//              TCONSPECTUS FUNCTION
function tConspectusRu(textRuForTconspectusSummarize, extractedRuSummaryFromTconspectusCallback, errorRequest) {

    var summarySize = 15;
    var requestToTconspectusOptions = {
        method: 'POST',
        url: 'http://tconspectus.pythonanywhere.com/summarization',
        gzip: true,
        headers: {
            'postman-token': 'ca0acbe7-fed7-827a-b288-0a55dfa4f34f',
            'accept-language': 'en-US,ru;q=0.8,uk;q=0.6,en;q=0.4,hy;q=0.2',
            'accept-encoding': 'gzip, deflate',
            referer: 'http://tconspectus.pythonanywhere.com/summarization',
            dnt: '1',
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'content-type': 'multipart/form-data; boundary=----WebKitFormBoundaryWbmEnC9zjSt5NPE2',
            'upgrade-insecure-requests': '1',
            origin: 'http://tconspectus.pythonanywhere.com',
            'cache-control': 'no-cache',
            connection: 'keep-alive',
            host: 'tconspectus.pythonanywhere.com'
        },
        body: '------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="mytext"\r\n\r\n' +
        textRuForTconspectusSummarize + '\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="action"\r\n\r\nsummarize\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="url_fieled"\r\n\r\n\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="upfile"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="action"\r\n\r\nupload\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="sumsize"\r\n\r\n' + summarySize + '\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="keywords"\r\n\r\non\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2\r\nContent-Disposition: form-data; name="kwis"\r\n\r\non\r\n------WebKitFormBoundaryWbmEnC9zjSt5NPE2--'
    };

    request(requestToTconspectusOptions, function (error, response, body) {
        if (error) errorRequest = error;

        extractedRuSummaryFromTconspectusCallback(body);

    });
}
//              TCONSPECTUS FUNCTION


//              getNewestFile
function getNewestFile(dir, files, callback) {
    if (!callback) return;
    if (!files || (files && files.length === 0)) {
        callback();
    }
    if (files.length === 1) {
        callback(files[0]);
    }
    var newest = {file: files[0]};
    var checked = 0;
    fs.stat(dir + newest.file, function (err, stats) {
        newest.mtime = stats.mtime;
        for (var i = 0; i < files.length; i++) {
            var file = files[i];
            (function (file) {
                fs.stat(file, function (err, stats) {
                    ++checked;
                    if (stats.mtime.getTime() > newest.mtime.getTime()) {
                        newest = {file: file, mtime: stats.mtime};
                    }
                    if (checked == files.length) {
                        callback(newest);
                    }
                });
            })(dir + file);
        }
    });
}
//              getNewestFile


/*--------------------------------------------------------------------------------------------------------------------*/


app.listen(8189, function () {
    winstonLog.info("Express server listening on port 8189");
});

/*
 Конспект: сладость программиста

 SETUP ENVIRONMENT

 Ubuntu 14.04.4 LTS (GNU/Linux 3.13.0-27-generic x86_64)
 mc
 wine
 nano
 libots0
 add ukrainian-stopwords for ots to uk.xml
 add uk_UA.UTF-8 locale // env LC_ALL=uk_UA.UTF-8 python3 nearestNeighbors.py
 add ru_RU.CP1251 locale
 add en_US.UTF-8 locale
 oracle java 8
 docears-pdf-inspector.jar //Docear’s PDF Inspector is a JAVA library that extracts titles from a PDF file not from the PDF’s metadata but from its full-text.
 nodejs
 npm
 catdoc
 docx2txt
 pdftotext
 Forever

 icybcluster.org.ua, ports
 23145 - ssh
 33145 - web app, internal port on server - 80
 32145 - REST API, internal port on server - 8189
 34145 - SPA internal port on server - 8188





 PDF кракозяблы решение
 cat ../kognit-lingvistik.txt | iconv -f utf8 -t iso-8859-1 | iconv -f cp1251 -t utf8 > ../kognit-lingvistik2.txt
 pdftotext -enc Latin1 file.pdf - | iconv -f cp1251 -t utf8 > file.txt

 -----------------------------------------------------------------------------------------------------------------------

 Множаться директории /consoles/console_
 -----------------------------------------------------------------------------------------------------------------------

 Подсчитать количество подключений
 при определённом количестве делать паузу и отправлять клиенту сообщение об ожидании

 server.getConnections(function (err, count) {
 console.log(count);
 });
 ------------------------------------------------------------------------------------------------------------------------

 Не верное имя файла

 "FILEPATH": [
 "/home/konspektService/consoles/console_1460365328512/inf_cp1251.txt"
 "FILEPATH": [
 "/home/konspektService/consoles/console_1460366051790/fileForAnalysisPdfCP1251.txt"


 Optimizing reading and writing using File Streams / threads
 Для больших файлов
 ------------------------------------------------------------------------------------------------------------------------

 Ubuntu 14.04.4 LTS (GNU/Linux 3.13.0-27-generic x86_64)

 Install Java JDK 8 on Ubuntu 14.04
 Step 1. Remove the OpenJDK from the system, if you have it already installed.

 sudo apt-get remove --purge openjdk*

 Step 2. Add the webupd8team Java PPA repository in your system.

 sudo add-apt-repository -y ppa:webupd8team/java

 Step 3. Install Java JDK 8

 sudo apt-get update
 sudo aptitude -y install oracle-java8-installer

 Step 4. Verify Installed Java Version.

 java -version
 ------------------------------------------------------------------------------------------------------------------------

 файлы с кирилическими  именами encodeURI !!!
 ------------------------------------------------------------------------------------------------------------------------


 рефакторінг імґн переменних для пост запросов

 ------------------------------------------------------------------------------------------------------------------------
 Проверку на язык для PDF

 ------------------------------------------------------------------------------------------------------------------------

 err_response_headers_too_big

 ------------------------------------------------------------------------------------------------------------------------


 */