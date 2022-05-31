const express = require('express');

// const bodyParser = require('body-parser');
const multer = require('multer');
const session = require('express-session');
let cookie_parser = require('cookie-parser');


const db = require('./database');
db.connect();


const app = express();
const path = require('path');
app.use('/static', express.static(path.join(__dirname, 'static')));

// Cookies
app.use(cookie_parser(process.env.SECRET_KEY))

// session 
app.use(session({ secret: process.env.SECRET_KEY, saveUninitialized: true, resave: true }));

//favicon
const favicon = require('serve-favicon');
app.use(favicon(path.join(__dirname, 'static', 'favicon.ico')));

app.set('view engine', 'ejs');

let crypto = require('crypto');

//Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// admin auth
function checkadmin(req, res, next) {
    if (next === undefined) {
        if (req.session.admin === 1) {
            return 1;
        }
        return 0;
    }
    if (req.session.admin === 1) {
        next();
    } else {
        return res.sendStatus(403);
    }
}


const redis = require('redis');
const redisStore = require('connect-redis')(session);
const client = redis.createClient();

app.use(session({
    secret: process.env.SECRET_KEY,
    store: new redisStore({ host: 'localhost', port: 8000, client: client, ttl: 260 }),
    saveUninitialized: false,
    resave: false
}));

//ENVs
const PORT = process.env.PORT || 8000;
app.listen(PORT, () =>
    console.log(`server started at ${PORT}`));

//Requests
const router = express.Router();


app.use('/', router);


router.get('/', (req, res) => {
    if (req.session.uname === undefined) {
        req.session.admin = 0
            // console.log(checkadmin(req));
        let sessionId = req.cookies.sessionId
        if (sessionId !== undefined) {
            db.query("select * from cookies where sessionId = " + db.escape(sessionId) + ";", (e, r, f) => {
                if (r[0] !== undefined) {
                    req.session.uname = r[0].uname;

                }
            })
            db.query("select * from users where uname = " + db.escape(req.session.uname) + ";", (e, r, f) => {
                if (r[0] !== undefined) {
                    req.session.admin = r[0].admin;
                }
            })
        }
    }

    if (req.session.uname === undefined) {
        db.query("select * from books;", (error, result, field) => {
            if (error) {
                return res.render("error");
            } else if (result[0] !== undefined) {
                return res.render("index", { totalbooks: result });
            }
            return res.render("index", { totalbooks: undefined });
        });

    } else {
        res.redirect('/user');
    }
});

router.post('/login', (req, res) => {
    if ((Boolean(req.body.uname) && Boolean(req.body.password)) === false) {
        return res.send("All fields are required");
    }
    db.query('select * from users where uname =' + db.escape(req.body.uname) + ';',
        (error, result, fields) => {
            if (error) {
                return res.send('Either user does not exist or user and password do not match');
            } else {
                if (result[0] != undefined && result[0].password === crypto.createHash('sha256').update(req.body.password + result[0].salt).digest('base64')) {
                    req.session.uname = result[0].uname;
                    req.session.admin = result[0].admin;
                    const nextSessionId = crypto.randomBytes(16).toString('base64')
                    res.cookie('sessionId', nextSessionId);
                    db.query("insert into cookies values (" + db.escape(nextSessionId) + "," + db.escape(req.session.uname) + ");", (e, r, f) => {
                        if (e) {
                            return res.render("error");
                        } else {

                            return res.redirect('/user');
                        }
                    })

                } else {
                    return res.send('Either user does not exist or user and password do not match');
                }
            }
        });
});


router.post('/changePassword', (req, res) => {
    let currPass = req.body.currPass;
    let newPass = req.body.newPass;
    let newPassC = req.body.newPassC;
    console.log(req.body);
    db.query("select * from users where uname = " + db.escape(req.session.uname) + ";", (error, result, field) => {
        if (error) {
            return res.render('error');
        } else if ((Boolean(currPass) && Boolean(newPass) && Boolean(newPassC)) === false) {
            return res.send("All fields are required");
        } else if (newPass !== newPassC) {
            return res.send("passwords do not match");
        } else if (crypto.createHash('sha256').update(currPass + result[0].salt).digest('base64') !== result[0].password) {
            res.send("Incorrect Password");
        } else {
            let salt = crypto.randomBytes(4).toString('hex');
            let hash = crypto.createHash('sha256').update(newPass + salt).digest('base64');
            db.query("update users set salt =" + db.escape(salt) + ", password = '" + hash + "' where uname=" + db.escape(req.session.uname) + ";", (error, result, field) => {
                if (error) {
                    return res.render("error");
                } else {
                    req.session.uname = undefined;
                    return res.send("Password Changed successfully.")
                }

            });
        }

    });

});

router.get('/logout', (req, res) => {
    req.session.uname = undefined;
    const sessionId = req.cookies.sessionId;
    req.session.destroy((err) => {
        if (err) {
            return res.render("error");
        }
    });
    db.query("delete from cookies where sessionId=" + db.escape(sessionId) + ";", (e, r, f) => {
        if (e) {
            return res.render("error");
        } else {
            res.clearCookie('sessionId');
            return res.redirect('/');
        }
    })


});


router.get('/user', (req, res) => {
    if (req.session.uname === undefined) {
        return res.redirect('/');
    } else if (checkadmin(req)) {
        return res.redirect("/admin");
    }
    db.query("select * from books;", (error1, result1, field) => {
        if (error1) {
            return res.render("error");
        } else {
            db.query("select books.* from books left join issuedbooks on issuedbooks.isbn = books.isbn and issuedbooks.uname =" + db.escape(req.session.uname) + " where issuedbooks.isbn is null and books.copies >0;", (error2, result2, field) => {
                if (error2) {
                    res.render("error")
                } else {
                    db.query("select books.* from books left join issuedbooks on issuedbooks.isbn = books.isbn and issuedbooks.uname =" + db.escape(req.session.uname) + " where issuedbooks.isbn is not null;", (error3, result3, field) => {
                        if (error3) {
                            res.render("error")
                        } else {
                            return res.render("user", { uname: req.session.uname, totalbooks: result1, newissuebooks: result2, issuedbooks: result3 });
                        }
                    })
                }
            })


        }
    });

});


router.get('/admin', checkadmin, (req, res) => {
    db.query("select * from books;", (error1, result1, field1) => {
        if (error1) {
            return res.render("error");
        } else {
            db.query("select books.*, requests.uname from books left join requests on books.isbn = requests.isbn and requests.status = 'issue' where requests.uname is not null;", (error2, result2, field2) => {
                if (error2) {
                    return res.render("error");
                } else {
                    db.query("select books.*, requests.uname from books left join requests on books.isbn = requests.isbn and requests.status = 'return' where requests.uname is not null;", (error3, result3, field3) => {
                        if (error3) {
                            return res.render("error");
                        } else {
                            return res.render("admin", { uname: req.session.uname, totalbooks: result1, approverequests: result2, approvereturns: result3 })
                        }
                    });
                }
            });
        }
    });

});



router.post('/register', (req, res) => {
    let name = req.body.uname;
    let password = req.body.password;
    let salt = crypto.randomBytes(4).toString('hex');
    const hash = crypto.createHash('sha256').update(password + salt).digest('base64');
    let passwordC = req.body.passwordC;
    if ((Boolean(name) && Boolean(password) && Boolean(passwordC)) === false) {
        return res.send("All fields are required");
    }
    db.query("select * from users where uname = " + db.escape(name) + ";",
        (error, result, field) => {
            if (result[0] === undefined) {
                if (name && (password === passwordC)) {
                    db.query("INSERT INTO users VALUES(" + db.escape(name) + "," + db.escape(salt) + ",'" + hash + "',0);");
                    req.session.uname = name;
                    req.session.admin = 0;
                    // db.query("create table " + db.escape(name).replace("'", "").replace("'", "") + "_issuedbooks" + " (isbn char(13), bookname letchar(256) );");
                    res.redirect('/user');
                } else if (password !== passwordC) {
                    res.send("Passwords didn't match");
                } else {
                    res.send("password must not be empty ");
                }
            } else {
                console.log(result);
                res.send("Username is not unique");
            }
        });
});

router.get('/register', (req, res) => {
    res.render('index');
});



// admin
//multer
let storage = multer.diskStorage({
    destination: (req, file, callBack) => {
        callBack(null, './static/images/'); // './satic/images/' directory name where save the file
    },
    filename: (req, file, callBack) => {
        callBack(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
    }
});

let upload = multer({ storage: storage });

// view books



// Add books
router.post('/addbooks', checkadmin, upload.single('bookcover'), (req, res) => {

    if (!req.file) {
        console.log("No file upload");
    } else {
        db.query("select * from books where isbn = " + db.escape(req.body.isbn) + ";",
            (error, result, field) => {
                if (error) {
                    return res.render("error");
                } else if (result[0] !== undefined) {
                    return res.send("ISBN is not unique");
                } else {
                    let imgsrc = "/static/images/" + req.file.filename;
                    let isbn = req.body.isbn
                    let bookname = req.body.bookname
                    let copies = req.body.copies
                    let bookdescription = req.body.bookdescription

                    db.query("insert into books values (" + db.escape(isbn) + "," + db.escape(bookname) + "," + db.escape(imgsrc) + ',' + db.escape(bookdescription) + "," + db.escape(copies) + ");", (error, result, field) => {
                        if (error) return res.render("error");
                    });
                    return res.send("Added successfully!");

                }
            });
    }

});
// Edit
router.post('/editbook', checkadmin, upload.single('bookcover'), (req, res) => {
    if (req.file) {
        let imgsrc = "/static/images/" + req.file.filename;
        let isbn = req.body.isbn
        let bookname = req.body.bookname
        let copies = req.body.copies
        let bookdescription = req.body.bookdescription

        db.query("update books set bookname= " + db.escape(bookname) + ", bookcoverpath=" + db.escape(imgsrc) + ', bookdescription=' + db.escape(bookdescription) + ",copies=" + db.escape(copies) + "where isbn =" + db.escape(isbn) + ";", (error, result, field) => {
            if (error) return res.render(error);
        });
        return res.send("Edited successfully!");

    } else {
        let isbn = req.body.isbn
        let bookname = req.body.bookname
        let copies = req.body.copies
        let bookdescription = req.body.bookdescription

        db.query("update books set bookname= " + db.escape(bookname) + ', bookdescription=' + db.escape(bookdescription) + ",copies=" + db.escape(copies) + "where isbn =" + db.escape(isbn) + ";", (error, result, field) => {
            if (error) return res.render(error);
        });
        return res.send("Edited successfully!");


    }
});

// Delete
router.post('/deletebook', checkadmin, (req, res) => {
    let isbn = req.body.isbn;
    db.query("delete from books where isbn=" + db.escape(isbn) + ';', (error, result, field) => {
        if (error) return res.render(error);
    });
    return res.send("Deletion successful!");
});

// issuse books
router.post("/newissue", (req, res) => {
    let isbn = req.body.isbn;
    db.query("select * from requests where status = 'issue' and isbn=" + db.escape(isbn) + " and uname= " + db.escape(req.session.uname) + ";", (e, r, f) => {
        if (e) {
            return res.render('error')
        } else if (r[0] === undefined) {
            db.query("insert into requests values(" + db.escape(isbn) + ',' + db.escape(req.session.uname) + ",'issue');", (error, result, field) => {
                if (error) return res.render(error);
            });
        }

    })
    return res.send("Admin will approve your issue request");
});

router.post('/approveissues', checkadmin, (req, res) => {

    let isbn = req.body.isbn;
    let name = req.body.uname;
    db.query("insert into issuedbooks values (" + db.escape(isbn) + "," + db.escape(name) + ");", (e1, r1, f) => {
        if (e1) {
            return res.render("error")
        } else {
            db.query("update books set copies=copies-1 where isbn=" + db.escape(isbn) + ";", (e2, r2, f) => {
                if (e2) {
                    return res.render("error")
                } else {
                    db.query("delete from requests where status = 'issue' and isbn=" + db.escape(isbn) + " and uname= " + db.escape(name) + ";", (e3, r3, f) => {
                        if (e3) {
                            return res.render("error")
                        } else {

                            return res.send("Approved issue request");
                        }
                    })
                }
            })
        }
    });

});



// return books

router.post("/newreturn", (req, res) => {
    let isbn = req.body.isbn;
    db.query("select * from requests where status = 'return' and isbn=" + db.escape(isbn) + " and uname= " + db.escape(req.session.uname) + ";", (e, r, f) => {
        if (e) {
            return res.render('error')
        } else if (r[0] === undefined) {
            db.query("insert into requests values(" + db.escape(isbn) + ',' + db.escape(req.session.uname) + ",'return');", (error, result, field) => {
                if (error) return res.render(error);
            });
        }

    })
    return res.send("Admin will approve your return request");
});

router.post('/approvereturns', checkadmin, (req, res) => {
    let isbn = req.body.isbn;
    let name = req.body.uname;
    db.query("delete from requests where status='return' and isbn=" + db.escape(isbn) + " and uname= " + db.escape(name) + ";", (e1, r1, f) => {
        if (e1) {
            return res.render("error")
        } else {
            db.query("update books set copies=copies+1 where isbn=" + db.escape(isbn) + ";", (e2, r2, f) => {
                if (e2) {
                    return res.render("error")
                } else {
                    db.query("delete from requests where status='return' and  isbn= " + db.escape(isbn) + " and uname=" + db.escape(name) + ";", (e3, r3, f) => {
                        if (e3) {
                            return res.render("error")
                        } else {
                            return res.send("Approved return");
                        }
                    })
                }
            })
        }
    });
});