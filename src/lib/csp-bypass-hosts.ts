// Known CSP allowlist bypass endpoints (JSONP and AngularJS hosts).
//
// Copied from Google's CSP Evaluator (https://github.com/google/csp-evaluator),
// files allowlist_bypasses/jsonp.ts and allowlist_bypasses/angular.ts at commit
// ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822.
//
// Copyright 2016 Google Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Only the data arrays are copied; the matching logic in this repository is
// our own (see matchBypassUrl below). Do not edit the arrays by hand: re-copy
// them from upstream and update the commit above.

export const CSP_EVALUATOR_COMMIT = 'ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822';

/** JSONP-like endpoints on commonly allowlisted origins. */
export const JSONP_URLS: readonly string[] = [
  '//bebezoo.1688.com/fragment/index.htm',
  '//www.google-analytics.com/gtm/js',
  '//googleads.g.doubleclick.net/pagead/conversion/1036918760/wcm',
  '//www.googleadservices.com/pagead/conversion/1070110417/wcm',
  '//www.google.com/tools/feedback/escalation-options',
  '//pin.aliyun.com/check_audio',
  '//offer.alibaba.com/market/CID100002954/5/fetchKeyword.do',
  '//ccrprod.alipay.com/ccr/arriveTime.json',
  '//group.aliexpress.com/ajaxAcquireGroupbuyProduct.do',
  '//detector.alicdn.com/2.7.3/index.php',
  '//suggest.taobao.com/sug',
  '//translate.google.com/translate_a/l',
  '//count.tbcdn.cn//counter3',
  '//wb.amap.com/channel.php',
  '//translate.googleapis.com/translate_a/l',
  '//afpeng.alimama.com/ex',
  '//accounts.google.com/o/oauth2/revoke',
  '//pagead2.googlesyndication.com/relatedsearch',
  '//yandex.ru/soft/browsers/check',
  '//api.facebook.com/restserver.php',
  '//mts0.googleapis.com/maps/vt',
  '//syndication.twitter.com/widgets/timelines/765840589183213568',
  '//www.youtube.com/profile_style',
  '//googletagmanager.com/gtm/js',
  '//mc.yandex.ru/watch/24306916/1',
  '//share.yandex.net/counter/gpp/',
  '//ok.go.mail.ru/lady_on_lady_recipes_r.json',
  '//d1f69o4buvlrj5.cloudfront.net/__efa_15_1_ornpba.xekq.arg/optout_check',
  '//www.googletagmanager.com/gtm/js',
  '//api.vk.com/method/wall.get',
  '//www.sharethis.com/get-publisher-info.php',
  '//google.ru/maps/vt',
  '//pro.netrox.sc/oapi/h_checksite.ashx',
  '//vimeo.com/api/oembed.json/',
  '//de.blog.newrelic.com/wp-admin/admin-ajax.php',
  '//ajax.googleapis.com/ajax/services/search/news',
  '//ssl.google-analytics.com/gtm/js',
  '//pubsub.pubnub.com/subscribe/demo/hello_world/',
  '//pass.yandex.ua/services',
  '//id.rambler.ru/script/topline_info.js',
  '//m.addthis.com/live/red_lojson/100eng.json',
  '//passport.ngs.ru/ajax/check',
  '//catalog.api.2gis.ru/ads/search',
  '//gum.criteo.com/sync',
  '//maps.google.com/maps/vt',
  '//ynuf.alipay.com/service/um.json',
  '//securepubads.g.doubleclick.net/gampad/ads',
  '//c.tiles.mapbox.com/v3/texastribune.tx-congress-cvap/6/15/26.grid.json',
  '//rexchange.begun.ru/banners',
  '//an.yandex.ru/page/147484',
  '//links.services.disqus.com/api/ping',
  '//api.map.baidu.com/',
  '//tj.gongchang.com/api/keywordrecomm/',
  '//data.gongchang.com/livegrail/',
  '//ulogin.ru/token.php',
  '//beta.gismeteo.ru/api/informer/layout.js/120x240-3/ru/',
  '//maps.googleapis.com/maps/api/js/GeoPhotoService.GetMetadata',
  '//a.config.skype.com/config/v1/Skype/908_1.33.0.111/SkypePersonalization',
  '//maps.beeline.ru/w',
  '//target.ukr.net/',
  '//www.meteoprog.ua/data/weather/informer/Poltava.js',
  '//cdn.syndication.twimg.com/widgets/timelines/599200054310604802',
  '//wslocker.ru/client/user.chk.php',
  '//community.adobe.com/CommunityPod/getJSON',
  '//maps.google.lv/maps/vt',
  '//dev.virtualearth.net/REST/V1/Imagery/Metadata/AerialWithLabels/26.318581',
  '//awaps.yandex.ru/10/8938/02400400.',
  '//a248.e.akamai.net/h5.hulu.com/h5.mp4',
  '//nominatim.openstreetmap.org/',
  '//plugins.mozilla.org/en-us/plugins_list.json',
  '//h.cackle.me/widget/32153/bootstrap',
  '//graph.facebook.com/1/',
  '//fellowes.ugc.bazaarvoice.com/data/reviews.json',
  '//widgets.pinterest.com/v3/pidgets/boards/ciciwin/hedgehog-squirrel-crafts/pins/',
  '//se.wikipedia.org/w/api.php',
  '//cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js',
  '//relap.io/api/v2/similar_pages_jsonp.js',
  '//c1n3.hypercomments.com/stream/subscribe',
  '//maps.google.de/maps/vt',
  '//books.google.com/books',
  '//connect.mail.ru/share_count',
  '//tr.indeed.com/m/newjobs',
  '//www-onepick-opensocial.googleusercontent.com/gadgets/proxy',
  '//www.panoramio.com/map/get_panoramas.php',
  '//client.siteheart.com/streamcli/client',
  '//www.facebook.com/restserver.php',
  '//autocomplete.travelpayouts.com/avia',
  '//www.googleapis.com/freebase/v1/topic/m/0344_',
  '//mts1.googleapis.com/mapslt/ft',
  '//publish.twitter.com/oembed',
  '//fast.wistia.com/embed/medias/o75jtw7654.json',
  '//partner.googleadservices.com/gampad/ads',
  '//pass.yandex.ru/services',
  '//gupiao.baidu.com/stocks/stockbets',
  '//widget.admitad.com/widget/init',
  '//api.instagram.com/v1/tags/partykungen23328/media/recent',
  '//video.media.yql.yahoo.com/v1/video/sapi/streams/063fb76c-6c70-38c5-9bbc-04b7c384de2b',
  '//ib.adnxs.com/jpt',
  '//pass.yandex.com/services',
  '//www.google.de/maps/vt',
  '//clients1.google.com/complete/search',
  '//api.userlike.com/api/chat/slot/proactive/',
  '//www.youku.com/index_cookielist/s/jsonp',
  '//mt1.googleapis.com/mapslt/ft',
  '//api.mixpanel.com/track/',
  '//wpd.b.qq.com/cgi/get_sign.php',
  '//pipes.yahooapis.com/pipes/pipe.run',
  '//gdata.youtube.com/feeds/api/videos/WsJIHN1kNWc',
  '//9.chart.apis.google.com/chart',
  '//cdn.syndication.twitter.com/moments/709229296800440320',
  '//api.flickr.com/services/feeds/photos_friends.gne',
  '//cbks0.googleapis.com/cbk',
  '//www.blogger.com/feeds/5578653387562324002/posts/summary/4427562025302749269',
  '//query.yahooapis.com/v1/public/yql',
  '//kecngantang.blogspot.com/feeds/posts/default/-/Komik',
  '//www.travelpayouts.com/widgets/50f53ce9ada1b54bcc000031.json',
  '//i.cackle.me/widget/32586/bootstrap',
  '//translate.yandex.net/api/v1.5/tr.json/detect',
  '//a.tiles.mapbox.com/v3/zentralmedia.map-n2raeauc.jsonp',
  '//maps.google.ru/maps/vt',
  '//c1n2.hypercomments.com/stream/subscribe',
  '//rec.ydf.yandex.ru/cookie',
  '//cdn.jsdelivr.net',
];

/** JSONP hosts whose bypass only works if the policy also allows eval(). */
export const JSONP_NEEDS_EVAL: readonly string[] = [
  'googletagmanager.com',
  'www.googletagmanager.com',
  'www.googleadservices.com',
  'google-analytics.com',
  'ssl.google-analytics.com',
  'www.google-analytics.com',
];

/** Hosts serving AngularJS builds that can be abused to bypass CSP. */
export const ANGULAR_URLS: readonly string[] = [
  '//gstatic.com/fsn/angular_js-bundle1.js',
  '//www.gstatic.com/fsn/angular_js-bundle1.js',
  '//www.googleadservices.com/pageadimg/imgad',
  '//yandex.st/angularjs/1.2.16/angular-cookies.min.js',
  '//yastatic.net/angularjs/1.2.23/angular.min.js',
  '//yuedust.yuedu.126.net/js/components/angular/angular.js',
  '//art.jobs.netease.com/script/angular.js',
  '//csu-c45.kxcdn.com/angular/angular.js',
  '//elysiumwebsite.s3.amazonaws.com/uploads/blog-media/rockstar/angular.min.js',
  '//inno.blob.core.windows.net/new/libs/AngularJS/1.2.1/angular.min.js',
  '//gift-talk.kakao.com/public/javascripts/angular.min.js',
  '//ajax.googleapis.com/ajax/libs/angularjs/1.2.0rc1/angular-route.min.js',
  '//master-sumok.ru/vendors/angular/angular-cookies.js',
  '//ayicommon-a.akamaihd.net/static/vendor/angular-1.4.2.min.js',
  '//pangxiehaitao.com/framework/angular-1.3.9/angular-animate.min.js',
  '//cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.16/angular.min.js',
  '//96fe3ee995e96e922b6b-d10c35bd0a0de2c718b252bc575fdb73.ssl.cf1.rackcdn.com/angular.js',
  '//oss.maxcdn.com/angularjs/1.2.20/angular.min.js',
  '//reports.zemanta.com/smedia/common/angularjs/1.2.11/angular.js',
  '//cdn.shopify.com/s/files/1/0225/6463/t/1/assets/angular-animate.min.js',
  '//parademanagement.com.s3-website-ap-southeast-1.amazonaws.com/js/angular.min.js',
  '//cdn.jsdelivr.net/angularjs/1.1.2/angular.min.js',
  '//eb2883ede55c53e09fd5-9c145fb03d93709ea57875d307e2d82e.ssl.cf3.rackcdn.com/components/angular-resource.min.js',
  '//andors-trail.googlecode.com/git/AndorsTrailEdit/lib/angular.min.js',
  '//cdn.walkme.com/General/EnvironmentTests/angular/angular.min.js',
  '//laundrymail.com/angular/angular.js',
  '//s3-eu-west-1.amazonaws.com/staticancpa/js/angular-cookies.min.js',
  '//collade.demo.stswp.com/js/vendor/angular.min.js',
  '//mrfishie.github.io/sailor/bower_components/angular/angular.min.js',
  '//askgithub.com/static/js/angular.min.js',
  '//services.amazon.com/solution-providers/assets/vendor/angular-cookies.min.js',
  '//raw.githubusercontent.com/angular/code.angularjs.org/master/1.0.7/angular-resource.js',
  '//prb-resume.appspot.com/bower_components/angular-animate/angular-animate.js',
  '//dl.dropboxusercontent.com/u/30877786/angular.min.js',
  '//static.tumblr.com/x5qdx0r/nPOnngtff/angular-resource.min_1_.js',
  '//storage.googleapis.com/assets-prod.urbansitter.net/us-sym/assets/vendor/angular-sanitize/angular-sanitize.min.js',
  '//twitter.github.io/labella.js/bower_components/angular/angular.min.js',
  '//cdn2-casinoroom.global.ssl.fastly.net/js/lib/angular-animate.min.js',
  '//www.adobe.com/devnet-apps/flashshowcase/lib/angular/angular.1.1.5.min.js',
  '//eternal-sunset.herokuapp.com/bower_components/angular/angular.js',
  '//cdn.bootcss.com/angular.js/1.2.0/angular.min.js',
];

export type BypassKind = 'jsonp' | 'angular';

export interface BypassMatch {
  kind: BypassKind;
  url: string;
  hostname: string;
}

/**
 * Checks one CSP host-source expression (e.g. "https://*.google.com",
 * "cdn.example.com/js/") against the known bypass lists, following CSP2
 * host/path matching rules. Scheme-only sources, keywords, nonces and hashes
 * never match. Returns the first match or null.
 *
 * `allowsEval` must be true when the same directive also allows
 * 'unsafe-eval'; some JSONP bypasses depend on it.
 */
export function matchBypassUrl(source: string, allowsEval: boolean): BypassMatch | null {
  const src = source.trim();
  if (!src || src.startsWith("'") || /^[a-z][a-z0-9+.-]*:$/i.test(src) || src === '*') return null;

  const schemeFree = src.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/^\/\//, '');
  const slash = schemeFree.indexOf('/');
  const hostPort = slash === -1 ? schemeFree : schemeFree.slice(0, slash);
  const path = slash === -1 ? '' : schemeFree.slice(slash);
  const host = hostPort.replace(/:(\d+|\*)$/, '').toLowerCase();
  if (!host) return null;

  const wildcard = host.startsWith('*.');
  const suffix = wildcard ? host.slice(1) : host; // ".example.com" when wildcard

  const check = (list: readonly string[], kind: BypassKind): BypassMatch | null => {
    for (const entry of list) {
      const u = new URL('https:' + entry);
      const h = u.hostname.toLowerCase();
      const hostOk = wildcard ? h.endsWith(suffix) : h === host;
      if (!hostOk) continue;
      if (path && path !== '/') {
        if (path.endsWith('/') ? !u.pathname.startsWith(path) : u.pathname !== path) continue;
      }
      if (kind === 'jsonp' && !allowsEval && JSONP_NEEDS_EVAL.includes(h)) continue;
      return { kind, url: entry, hostname: h };
    }
    return null;
  };

  return check(ANGULAR_URLS, 'angular') ?? check(JSONP_URLS, 'jsonp');
}
