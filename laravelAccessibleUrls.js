function laravelAccessibleUrls() {

    // to convert dictionary txt to array you can use online tools
    this.getUrls = function () {
        return [
            '/admin',
            '/admin/profile',
            '/admin/login',
            '/vendor/composer/installed.json',
            '/vendor/bin/carbon',
            '/artisan',
            '/.gitignore',
            '/webpack.mix.js',
            '/access.log',
            '/error.log',
            '/composer.lock',
            '/composer.json',
            '/package.json',
            '/storage/logs/laravel.log',
            '/storage/oauth-public.key',
            '/storage/oauth-private.key',
            '/public/login',
            '/robots.txt',
            '/sitemap.xml',
            '/admin/user',
            'oauth/clients'
        ];
    }

}