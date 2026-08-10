from parser import JSParser

angular_route_code = """
(function () {
    'use strict';
    angular.module('app')
        .config(config);

    config.$inject = ['$stateProvider', '$locationProvider', '$urlRouterProvider'];

    function config($stateProvider, $locationProvider, $urlRouterProvider) {
        $stateProvider
            .state('landing', {
                url: '/home',
                views: {
                    '': {
                        templateUrl: 'scripts/app/home/landing.html',
                        controller: 'LandingController',
                        controllerAs: 'vm',
                        title: 'Home'
                    }
                },
                title: 'Home'
            })
            .state('account-layout.signup', {
                title: 'Register',
                url: '/user/register',
                views: {
                    'main': {
                        templateUrl: 'scripts/app/account/register.html',
                        controllerAs: 'vm',
                        controller: 'registerController',
                        title: 'Register'
                    }
                }
            })
            .state('account-layout.login', {
                title: 'Login',
                url: '/user/login/:candidateId',
                views: {
                    'main': {
                        templateUrl: 'scripts/app/account/login.html',
                        controllerAs: 'vm',
                        controller: 'loginController',
                        title: 'Login'
                    }
                }
            })
            .state('account-layout.forgot', {
                url: '/user/password/reset',
                views: {
                    'main': {
                        templateUrl: 'scripts/app/account/forgot-password.html',
                        controllerAs: 'vm',
                        controller: 'forgotPasswordController'
                    }
                },
                title: 'Forgot Password'
            })
            .state('account-layout.reset', {
                url: '/user/account/password/reset/:code',
                views: {
                    'main': {
                        templateUrl: 'scripts/app/account/reset.html',
                        controllerAs: 'vm',
                        controller: 'forgotPasswordController'
                    }
                },
                title: 'Reset Password'
            })
            .state('account-layout.accept-invitation', {
                url: '/user/invited/:key',
                views: {
                    'main': {
                        templateUrl: 'scripts/app/account/accept-invitation.html',
                        controllerAs: 'vm',
                        controller: 'acceptInvitationController',
                        resolve: {
                            recruiter: [
                                'recruiterAccountService', '$stateParams', 'avatarInitials', function (recruiterAccountService, $stateParams, avatarInitials) {
                                    var loadData = { InvitationId: $stateParams.key };
                                    return recruiterAccountService.getRecruiterByInvitationId(loadData).then(function (data) {
                                        if (data == undefined) {
                                            return null;
                                        }
                                        return {
                                            recruiterId: data.id,
                                            organizationId: data.organizationId,
                                            organizationName: data.organizationName,
                                            email: data.email,
                                            firstName: data.firstName,
                                            lastName: data.lastName,
                                            pictureUrl: data.pictureUrl.replace(/\\s/g, '').length ? data.pictureUrl : avatarInitials.getAvatarDataUrl(data.firstName + ' ' + data.lastName),
                                            role: data.role,
                                            status: data.status
                                        };
                                    });
                                }
                            ]
                        }
                    }
                },
                title: 'User Invitation'
            })
            .state('resume-edit', {
                url: '/resume/:pageNumber/:pcId/edit',
                params: {
                    resume: null
                },
                views: {
                    '': {
                        templateUrl: 'scripts/app/resume/resume-edit.html',
                        controller: 'ResumeEditController',
                        controllerAs: 'vm'
                    }
                },
                resolve: {
                    selectedResume: ['resumeService', '$stateParams', function (resumeService, $stateParams) {
                        return resumeService.getResumeById({ Id: $stateParams.pcId });
                    }]
                },
                title: 'Profile Details'
            });
    }
})();
"""

def test_angular():
    print("[*] Testing Angular UI Router JS Extraction...")
    parser = JSParser()
    res = parser.parse_code(angular_route_code, source_url="https://scholarship.mohesr.gov.ae/Scripts/app/app.route.js")

    print(f"[+] Total Extracted Endpoints & Routes: {len(res.endpoints)}")
    for ep in res.endpoints:
        print(f"  - [{ep.category}] {ep.method} {ep.path} (BOLA: {ep.is_bola_candidate}, Params: {ep.parameters})")

if __name__ == "__main__":
    test_angular()
