var Queries = require('../routes/searchQueries');

exports.search_products = function( req, res, next ) {
    req.getConnection(function(err, connection){
        
        var searchValue ='%' + req.params.searchValue + '%';
        var searchResultsCb = function( results){
            
            res.render('products_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

        var queries = new Queries(connection);
        queries.findProductByName(searchValue)
            .then(searchResultsCb)
            .catch(function(err){
                next(err);
            });
        
    })
};

exports.search_grouped_sales = function(req, res, next){
    req.getConnection(function(err, connection){
        var searchValue = "%" + req.params.searchValue + "%";        
        var searchResults = function(results){

            res.render('gsales_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

            var querieList = new Queries(connection);
            querieList.findGroupedSales(searchValue)
                .then(searchResults)
                .catch(function(err){
                       next(err);
                });
    });
};

exports.search_all_sales = function(req, res, next){
    req.getConnection(function(err, connection){        
        var searchValue = "%" + req.params.searchValue + "%";        
        var searchResults = function(results){
            
            res.render('allsales_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

            var querieList = new Queries(connection);
            querieList.allSales(searchValue)
                .then(searchResults)
                .catch(function(err){
                next(err);
            });
        
    });
};

exports.search_product_earnings = function(req, res, next){
    req.getConnection(function(err, connection){
        
        var searchValue = "%" + req.params.searchValue + "%";        
        var searchResults = function(results){
            
            res.render('earnings_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

        var querieList = new Queries(connection);
            querieList.product_earnings(searchValue)
                .then(searchResults)
                .catch(function(err){
                next(err);
            });
        
    });
};

exports.search_categories = function(req, res, next){
    req.getConnection(function(err, connection){
        var searchValue = "%" + req.params.searchValue + "%";        
        var searchResults = function( results){ 
            res.render('category_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

        var allCategories = new Queries(connection);
            allCategories.categories(searchValue)
            .then(searchResults)
            .catch(function(err){
                next(err);
        }); 
    })
};

exports.search_category_sales = function(req, res, next){
    req.getConnection(function(err, connection){
        
        var searchValue = "%" + req.params.searchValue + "%";        
        var searchResults = function(results){
            
            res.render('category_sales_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

        var allCategories = new Queries(connection);
        allCategories.category_sales(searchValue)
            .then(searchResults)
            .catch(function(err){
            next(err);
        });
        
    });
};

exports.search_category_earnings = function(req, res, next){
    req.getConnection(function(err, connection){
        
        var searchValue = "%" + req.params.searchValue + "%";        
        var searchResults = function(results){
            
            res.render('category_earnings_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

        var categoryEarnings = new Queries(connection);
        categoryEarnings.category_earnings(searchValue)
            .then(searchResults)
            .catch(function(err){
            next(err);
        });
        
    });
};

exports.search_suppliers = function(req, res, next){
    req.getConnection(function(err, connection){
        var searchValue = "%" + req.params.searchValue + "%";        
        var searchResults = function(results){

            res.render('suppliers_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

         var querieList = new Queries(connection);
            querieList.suppliers(searchValue)
                .then(searchResults)
                .catch(function(err){
                    next(err);
            });

    });
};

exports.search_purchases = function(req, res, next){
    req.getConnection(function(err, connection){
        var searchValue = "%" + req.params.searchValue + "%";        
        var searchResults = function(results){
            
            res.render('purchases_search', {
                username : req.session.user,
                products : results,
                layout : false
            });            
        };

        var allPurchases = new Queries(connection);
        allPurchases.purchases(searchValue)
            .then(searchResults)
            .catch(function(err){
            next(err);
        });
        
    });
};