#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *
from .bitcoin_funcs import *
from .misc_funcs_and_vars import *
from .CoinFromKey import *
from .StealthAddress import *
from .Bip32Key import *

class Bip39EngClass(object):
    """
    Simple object to hold information about a BIP39 English wordlist.

    >>> doctester = Bip39EngClass("turtle front uncle idea crush write shrug there lottery flower risk shell")
    >>> doctester.hex
    'eaebabb2383351fd31d703840b32e9e2'
    >>> doctester.bip32seed
    '4ef6e8484a846392f996b15283906b73be4ec100859ce68689d5a0fad7f761745b86d70ea5f5c43e4cc93ce4b82b3d9aeed7f85d503fac00b10ebbc150399100'
    >>> doctester.setPBKDF2password("TREZOR")
    >>> doctester.bip32seed
    'bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c404f18d7b05818c95ef3ca1e5146646856c461c073169467511680876c'
    >>> str(Bip32Key(Bip39EngClass("legal winner thank year wave sausage worth useful legal winner thank yellow","TREZOR").bip32seed))
    'xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq'
    >>> Bip39EngClass.hex_to_wordlist("00000000000000000000000000000000")
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    >>> Bip39EngClass.wordlist_to_hex("board flee heavy tunnel powder denial science ski answer betray cargo cat")
    '18ab19a9f54a9274f03e5209a2ac8a91'
    >>> Bip39EngClass.wordlist_to_hex("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    '00000000000000000000000000000000'
    """

    # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    BIP0039_ENG_WORDLIST = [
        'abandon','ability','able','about','above','absent','absorb',
        'abstract','absurd','abuse','access','accident','account',
        'accuse','achieve','acid','acoustic','acquire','across','act',
        'action','actor','actress','actual','adapt','add','addict',
        'address','adjust','admit','adult','advance','advice',
        'aerobic','affair','afford','afraid','again','age','agent',
        'agree','ahead','aim','air','airport','aisle','alarm','album',
        'alcohol','alert','alien','all','alley','allow','almost',
        'alone','alpha','already','also','alter','always','amateur',
        'amazing','among','amount','amused','analyst','anchor',
        'ancient','anger','angle','angry','animal','ankle','announce',
        'annual','another','answer','antenna','antique','anxiety',
        'any','apart','apology','appear','apple','approve','april',
        'arch','arctic','area','arena','argue','arm','armed','armor',
        'army','around','arrange','arrest','arrive','arrow','art',
        'artefact','artist','artwork','ask','aspect','assault',
        'asset','assist','assume','asthma','athlete','atom','attack',
        'attend','attitude','attract','auction','audit','august',
        'aunt','author','auto','autumn','average','avocado','avoid',
        'awake','aware','away','awesome','awful','awkward','axis',
        'baby','bachelor','bacon','badge','bag','balance','balcony',
        'ball','bamboo','banana','banner','bar','barely','bargain',
        'barrel','base','basic','basket','battle','beach','bean',
        'beauty','because','become','beef','before','begin','behave',
        'behind','believe','below','belt','bench','benefit','best',
        'betray','better','between','beyond','bicycle','bid','bike',
        'bind','biology','bird','birth','bitter','black','blade',
        'blame','blanket','blast','bleak','bless','blind','blood',
        'blossom','blouse','blue','blur','blush','board','boat',
        'body','boil','bomb','bone','bonus','book','boost','border',
        'boring','borrow','boss','bottom','bounce','box','boy',
        'bracket','brain','brand','brass','brave','bread','breeze',
        'brick','bridge','brief','bright','bring','brisk','broccoli',
        'broken','bronze','broom','brother','brown','brush','bubble',
        'buddy','budget','buffalo','build','bulb','bulk','bullet',
        'bundle','bunker','burden','burger','burst','bus','business',
        'busy','butter','buyer','buzz','cabbage','cabin','cable',
        'cactus','cage','cake','call','calm','camera','camp','can',
        'canal','cancel','candy','cannon','canoe','canvas','canyon',
        'capable','capital','captain','car','carbon','card','cargo',
        'carpet','carry','cart','case','cash','casino','castle',
        'casual','cat','catalog','catch','category','cattle','caught',
        'cause','caution','cave','ceiling','celery','cement','census',
        'century','cereal','certain','chair','chalk','champion',
        'change','chaos','chapter','charge','chase','chat','cheap',
        'check','cheese','chef','cherry','chest','chicken','chief',
        'child','chimney','choice','choose','chronic','chuckle',
        'chunk','churn','cigar','cinnamon','circle','citizen','city',
        'civil','claim','clap','clarify','claw','clay','clean',
        'clerk','clever','click','client','cliff','climb','clinic',
        'clip','clock','clog','close','cloth','cloud','clown','club',
        'clump','cluster','clutch','coach','coast','coconut','code',
        'coffee','coil','coin','collect','color','column','combine',
        'come','comfort','comic','common','company','concert',
        'conduct','confirm','congress','connect','consider','control',
        'convince','cook','cool','copper','copy','coral','core',
        'corn','correct','cost','cotton','couch','country','couple',
        'course','cousin','cover','coyote','crack','cradle','craft',
        'cram','crane','crash','crater','crawl','crazy','cream',
        'credit','creek','crew','cricket','crime','crisp','critic',
        'crop','cross','crouch','crowd','crucial','cruel','cruise',
        'crumble','crunch','crush','cry','crystal','cube','culture',
        'cup','cupboard','curious','current','curtain','curve',
        'cushion','custom','cute','cycle','dad','damage','damp',
        'dance','danger','daring','dash','daughter','dawn','day',
        'deal','debate','debris','decade','december','decide',
        'decline','decorate','decrease','deer','defense','define',
        'defy','degree','delay','deliver','demand','demise','denial',
        'dentist','deny','depart','depend','deposit','depth','deputy',
        'derive','describe','desert','design','desk','despair',
        'destroy','detail','detect','develop','device','devote',
        'diagram','dial','diamond','diary','dice','diesel','diet',
        'differ','digital','dignity','dilemma','dinner','dinosaur',
        'direct','dirt','disagree','discover','disease','dish',
        'dismiss','disorder','display','distance','divert','divide',
        'divorce','dizzy','doctor','document','dog','doll','dolphin',
        'domain','donate','donkey','donor','door','dose','double',
        'dove','draft','dragon','drama','drastic','draw','dream',
        'dress','drift','drill','drink','drip','drive','drop','drum',
        'dry','duck','dumb','dune','during','dust','dutch','duty',
        'dwarf','dynamic','eager','eagle','early','earn','earth',
        'easily','east','easy','echo','ecology','economy','edge',
        'edit','educate','effort','egg','eight','either','elbow',
        'elder','electric','elegant','element','elephant','elevator',
        'elite','else','embark','embody','embrace','emerge','emotion',
        'employ','empower','empty','enable','enact','end','endless',
        'endorse','enemy','energy','enforce','engage','engine',
        'enhance','enjoy','enlist','enough','enrich','enroll',
        'ensure','enter','entire','entry','envelope','episode',
        'equal','equip','era','erase','erode','erosion','error',
        'erupt','escape','essay','essence','estate','eternal',
        'ethics','evidence','evil','evoke','evolve','exact','example',
        'excess','exchange','excite','exclude','excuse','execute',
        'exercise','exhaust','exhibit','exile','exist','exit',
        'exotic','expand','expect','expire','explain','expose',
        'express','extend','extra','eye','eyebrow','fabric','face',
        'faculty','fade','faint','faith','fall','false','fame',
        'family','famous','fan','fancy','fantasy','farm','fashion',
        'fat','fatal','father','fatigue','fault','favorite','feature',
        'february','federal','fee','feed','feel','female','fence',
        'festival','fetch','fever','few','fiber','fiction','field',
        'figure','file','film','filter','final','find','fine',
        'finger','finish','fire','firm','first','fiscal','fish','fit',
        'fitness','fix','flag','flame','flash','flat','flavor','flee',
        'flight','flip','float','flock','floor','flower','fluid',
        'flush','fly','foam','focus','fog','foil','fold','follow',
        'food','foot','force','forest','forget','fork','fortune',
        'forum','forward','fossil','foster','found','fox','fragile',
        'frame','frequent','fresh','friend','fringe','frog','front',
        'frost','frown','frozen','fruit','fuel','fun','funny',
        'furnace','fury','future','gadget','gain','galaxy','gallery',
        'game','gap','garage','garbage','garden','garlic','garment',
        'gas','gasp','gate','gather','gauge','gaze','general',
        'genius','genre','gentle','genuine','gesture','ghost','giant',
        'gift','giggle','ginger','giraffe','girl','give','glad',
        'glance','glare','glass','glide','glimpse','globe','gloom',
        'glory','glove','glow','glue','goat','goddess','gold','good',
        'goose','gorilla','gospel','gossip','govern','gown','grab',
        'grace','grain','grant','grape','grass','gravity','great',
        'green','grid','grief','grit','grocery','group','grow',
        'grunt','guard','guess','guide','guilt','guitar','gun','gym',
        'habit','hair','half','hammer','hamster','hand','happy',
        'harbor','hard','harsh','harvest','hat','have','hawk',
        'hazard','head','health','heart','heavy','hedgehog','height',
        'hello','helmet','help','hen','hero','hidden','high','hill',
        'hint','hip','hire','history','hobby','hockey','hold','hole',
        'holiday','hollow','home','honey','hood','hope','horn',
        'horror','horse','hospital','host','hotel','hour','hover',
        'hub','huge','human','humble','humor','hundred','hungry',
        'hunt','hurdle','hurry','hurt','husband','hybrid','ice',
        'icon','idea','identify','idle','ignore','ill','illegal',
        'illness','image','imitate','immense','immune','impact',
        'impose','improve','impulse','inch','include','income',
        'increase','index','indicate','indoor','industry','infant',
        'inflict','inform','inhale','inherit','initial','inject',
        'injury','inmate','inner','innocent','input','inquiry',
        'insane','insect','inside','inspire','install','intact',
        'interest','into','invest','invite','involve','iron','island',
        'isolate','issue','item','ivory','jacket','jaguar','jar',
        'jazz','jealous','jeans','jelly','jewel','job','join','joke',
        'journey','joy','judge','juice','jump','jungle','junior',
        'junk','just','kangaroo','keen','keep','ketchup','key','kick',
        'kid','kidney','kind','kingdom','kiss','kit','kitchen','kite',
        'kitten','kiwi','knee','knife','knock','know','lab','label',
        'labor','ladder','lady','lake','lamp','language','laptop',
        'large','later','latin','laugh','laundry','lava','law','lawn',
        'lawsuit','layer','lazy','leader','leaf','learn','leave',
        'lecture','left','leg','legal','legend','leisure','lemon',
        'lend','length','lens','leopard','lesson','letter','level',
        'liar','liberty','library','license','life','lift','light',
        'like','limb','limit','link','lion','liquid','list','little',
        'live','lizard','load','loan','lobster','local','lock',
        'logic','lonely','long','loop','lottery','loud','lounge',
        'love','loyal','lucky','luggage','lumber','lunar','lunch',
        'luxury','lyrics','machine','mad','magic','magnet','maid',
        'mail','main','major','make','mammal','man','manage',
        'mandate','mango','mansion','manual','maple','marble','march',
        'margin','marine','market','marriage','mask','mass','master',
        'match','material','math','matrix','matter','maximum','maze',
        'meadow','mean','measure','meat','mechanic','medal','media',
        'melody','melt','member','memory','mention','menu','mercy',
        'merge','merit','merry','mesh','message','metal','method',
        'middle','midnight','milk','million','mimic','mind','minimum',
        'minor','minute','miracle','mirror','misery','miss','mistake',
        'mix','mixed','mixture','mobile','model','modify','mom',
        'moment','monitor','monkey','monster','month','moon','moral',
        'more','morning','mosquito','mother','motion','motor',
        'mountain','mouse','move','movie','much','muffin','mule',
        'multiply','muscle','museum','mushroom','music','must',
        'mutual','myself','mystery','myth','naive','name','napkin',
        'narrow','nasty','nation','nature','near','neck','need',
        'negative','neglect','neither','nephew','nerve','nest','net',
        'network','neutral','never','news','next','nice','night',
        'noble','noise','nominee','noodle','normal','north','nose',
        'notable','note','nothing','notice','novel','now','nuclear',
        'number','nurse','nut','oak','obey','object','oblige',
        'obscure','observe','obtain','obvious','occur','ocean',
        'october','odor','off','offer','office','often','oil','okay',
        'old','olive','olympic','omit','once','one','onion','online',
        'only','open','opera','opinion','oppose','option','orange',
        'orbit','orchard','order','ordinary','organ','orient',
        'original','orphan','ostrich','other','outdoor','outer',
        'output','outside','oval','oven','over','own','owner',
        'oxygen','oyster','ozone','pact','paddle','page','pair',
        'palace','palm','panda','panel','panic','panther','paper',
        'parade','parent','park','parrot','party','pass','patch',
        'path','patient','patrol','pattern','pause','pave','payment',
        'peace','peanut','pear','peasant','pelican','pen','penalty',
        'pencil','people','pepper','perfect','permit','person','pet',
        'phone','photo','phrase','physical','piano','picnic',
        'picture','piece','pig','pigeon','pill','pilot','pink',
        'pioneer','pipe','pistol','pitch','pizza','place','planet',
        'plastic','plate','play','please','pledge','pluck','plug',
        'plunge','poem','poet','point','polar','pole','police','pond',
        'pony','pool','popular','portion','position','possible',
        'post','potato','pottery','poverty','powder','power',
        'practice','praise','predict','prefer','prepare','present',
        'pretty','prevent','price','pride','primary','print',
        'priority','prison','private','prize','problem','process',
        'produce','profit','program','project','promote','proof',
        'property','prosper','protect','proud','provide','public',
        'pudding','pull','pulp','pulse','pumpkin','punch','pupil',
        'puppy','purchase','purity','purpose','purse','push','put',
        'puzzle','pyramid','quality','quantum','quarter','question',
        'quick','quit','quiz','quote','rabbit','raccoon','race',
        'rack','radar','radio','rail','rain','raise','rally','ramp',
        'ranch','random','range','rapid','rare','rate','rather',
        'raven','raw','razor','ready','real','reason','rebel',
        'rebuild','recall','receive','recipe','record','recycle',
        'reduce','reflect','reform','refuse','region','regret',
        'regular','reject','relax','release','relief','rely','remain',
        'remember','remind','remove','render','renew','rent','reopen',
        'repair','repeat','replace','report','require','rescue',
        'resemble','resist','resource','response','result','retire',
        'retreat','return','reunion','reveal','review','reward',
        'rhythm','rib','ribbon','rice','rich','ride','ridge','rifle',
        'right','rigid','ring','riot','ripple','risk','ritual',
        'rival','river','road','roast','robot','robust','rocket',
        'romance','roof','rookie','room','rose','rotate','rough',
        'round','route','royal','rubber','rude','rug','rule','run',
        'runway','rural','sad','saddle','sadness','safe','sail',
        'salad','salmon','salon','salt','salute','same','sample',
        'sand','satisfy','satoshi','sauce','sausage','save','say',
        'scale','scan','scare','scatter','scene','scheme','school',
        'science','scissors','scorpion','scout','scrap','screen',
        'script','scrub','sea','search','season','seat','second',
        'secret','section','security','seed','seek','segment',
        'select','sell','seminar','senior','sense','sentence',
        'series','service','session','settle','setup','seven',
        'shadow','shaft','shallow','share','shed','shell','sheriff',
        'shield','shift','shine','ship','shiver','shock','shoe',
        'shoot','shop','short','shoulder','shove','shrimp','shrug',
        'shuffle','shy','sibling','sick','side','siege','sight',
        'sign','silent','silk','silly','silver','similar','simple',
        'since','sing','siren','sister','situate','six','size',
        'skate','sketch','ski','skill','skin','skirt','skull','slab',
        'slam','sleep','slender','slice','slide','slight','slim',
        'slogan','slot','slow','slush','small','smart','smile',
        'smoke','smooth','snack','snake','snap','sniff','snow','soap',
        'soccer','social','sock','soda','soft','solar','soldier',
        'solid','solution','solve','someone','song','soon','sorry',
        'sort','soul','sound','soup','source','south','space','spare',
        'spatial','spawn','speak','special','speed','spell','spend',
        'sphere','spice','spider','spike','spin','spirit','split',
        'spoil','sponsor','spoon','sport','spot','spray','spread',
        'spring','spy','square','squeeze','squirrel','stable',
        'stadium','staff','stage','stairs','stamp','stand','start',
        'state','stay','steak','steel','stem','step','stereo','stick',
        'still','sting','stock','stomach','stone','stool','story',
        'stove','strategy','street','strike','strong','struggle',
        'student','stuff','stumble','style','subject','submit',
        'subway','success','such','sudden','suffer','sugar','suggest',
        'suit','summer','sun','sunny','sunset','super','supply',
        'supreme','sure','surface','surge','surprise','surround',
        'survey','suspect','sustain','swallow','swamp','swap','swarm',
        'swear','sweet','swift','swim','swing','switch','sword',
        'symbol','symptom','syrup','system','table','tackle','tag',
        'tail','talent','talk','tank','tape','target','task','taste',
        'tattoo','taxi','teach','team','tell','ten','tenant','tennis',
        'tent','term','test','text','thank','that','theme','then',
        'theory','there','they','thing','this','thought','three',
        'thrive','throw','thumb','thunder','ticket','tide','tiger',
        'tilt','timber','time','tiny','tip','tired','tissue','title',
        'toast','tobacco','today','toddler','toe','together','toilet',
        'token','tomato','tomorrow','tone','tongue','tonight','tool',
        'tooth','top','topic','topple','torch','tornado','tortoise',
        'toss','total','tourist','toward','tower','town','toy',
        'track','trade','traffic','tragic','train','transfer','trap',
        'trash','travel','tray','treat','tree','trend','trial',
        'tribe','trick','trigger','trim','trip','trophy','trouble',
        'truck','true','truly','trumpet','trust','truth','try','tube',
        'tuition','tumble','tuna','tunnel','turkey','turn','turtle',
        'twelve','twenty','twice','twin','twist','two','type',
        'typical','ugly','umbrella','unable','unaware','uncle',
        'uncover','under','undo','unfair','unfold','unhappy',
        'uniform','unique','unit','universe','unknown','unlock',
        'until','unusual','unveil','update','upgrade','uphold','upon',
        'upper','upset','urban','urge','usage','use','used','useful',
        'useless','usual','utility','vacant','vacuum','vague','valid',
        'valley','valve','van','vanish','vapor','various','vast',
        'vault','vehicle','velvet','vendor','venture','venue','verb',
        'verify','version','very','vessel','veteran','viable',
        'vibrant','vicious','victory','video','view','village',
        'vintage','violin','virtual','virus','visa','visit','visual',
        'vital','vivid','vocal','voice','void','volcano','volume',
        'vote','voyage','wage','wagon','wait','walk','wall','walnut',
        'want','warfare','warm','warrior','wash','wasp','waste',
        'water','wave','way','wealth','weapon','wear','weasel',
        'weather','web','wedding','weekend','weird','welcome','west',
        'wet','whale','what','wheat','wheel','when','where','whip',
        'whisper','wide','width','wife','wild','will','win','window',
        'wine','wing','wink','winner','winter','wire','wisdom','wise',
        'wish','witness','wolf','woman','wonder','wood','wool','word',
        'work','world','worry','worth','wrap','wreck','wrestle',
        'wrist','write','wrong','yard','year','yellow','you','young',
        'youth','zebra','zero','zone','zoo']

    def __init__(self,unknowninput="",password=""):
        super(Bip39EngClass,self).__init__()
        self.unknowninput = unknowninput
        self.password = password
        if self.unknowninput != "":
            try:
                self.setWordlist(self.unknowninput)
            except Exception as e:
                try:
                    self.setHex(self.unknowninput)
                except Exception as f:
                    self.wordlist = str("")
                    self.hex = str("")
                    raise TypeError("Initialization first input must be blank, hex, or a valid bip39 word list of lowercase words separated by a single space.  Wordlist decode attempt exception was: " + str(e) + ", and hex decode attempt exception thrown was: " + str(f))
                else:
                    self.hex = self.unknowninput
                    self.wordlist = Bip39EngClass.hex_to_wordlist(self.hex)
            else:
                self.wordlist = str("")
                for word in self.unknowninput:
                    self.wordlist = self.wordlist + word + " "
                self.wordlist = str(self.wordlist).lower().rstrip(" ")
                self.hex = Bip39EngClass.wordlist_to_hex(self.wordlist)
        else:
            self.wordlist = str("")
            self.hex = str("")
        self.unknowninput = None
        if self.password != "":
            self.password = str(self.password)
            if int(sys.version_info.major) == 2:
                self.password = unicode(self.password)
            self.password = unicodedata.normalize('NFC',self.password)
            self.password = str(self.password)
        else:
            self.password = str("")
        if self.wordlist != "":
            self.pbkdf2(self.wordlist,self.password)
        else:
            self.bip32seed = str("")
        if self.wordlist and "  " in self.wordlist:
            self.wordlist = str(self.wordlist).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")

    def __str__(self):
        return self.wordlist

    def setPBKDF2password(self,password):
        self.password = str(password)
        if int(sys.version_info.major) == 2:
            self.password = unicode(self.password)
        self.password = unicodedata.normalize('NFC',self.password)
        self.password = str(self.password)
        if self.wordlist != "":
            self.pbkdf2(self.wordlist,self.password)

    def setWordlist(self,wordlist):
        self.wordlist = str(wordlist)
        if int(sys.version_info.major) == 2:
            self.wordlist = unicode(self.wordlist)
        self.wordlist = unicodedata.normalize('NFC',self.wordlist)
        self.wordlist = str(self.wordlist).lower()
        if self.wordlist and "  " in self.wordlist:
            self.wordlist = str(self.wordlist).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        try:
            self.wordlistarray = self.wordlist.split()
        except:
            raise TypeError("Please make sure the input is a str of words, each separated by a single space, with no punctuation.")
        for word in self.wordlistarray:
            if word not in Bip39EngClass.BIP0039_ENG_WORDLIST:
                raise TypeError("Word: '" + str(word) + "' is not in the BIP38 English wordlist. Check spelling maybe.")
        self.wordlist = str("")
        for word in self.wordlistarray:
            self.wordlist = self.wordlist + str(" ") + str(word)
        self.wordlist = self.wordlist.rstrip(" ")
        if len(self.wordlistarray) > 93:
            self.wordlist = str("")
            self.hex = str("")
            raise TypeError("Worldlist size too large.  Greater than 992 bits of entropy not supported.")
        if len(self.wordlistarray) < 3:
            self.wordlist = str("")
            self.hex = str("")
            raise TypeError("Worldlist size too small.  Less than 32 bits of entropy not supported.")
        if len(self.wordlistarray) % 3:
            self.wordlist = str("")
            self.hex = str("")
            raise TypeError("Worldlist has too many/few words.  Must be in 3-word multiples.")
        self.wordlistarray = None
        try:
            self.hex = Bip39EngClass.wordlist_to_hex(self.wordlist)
        except Exception as e:
            self.wordlist = str("")
            self.hex = str("")
            raise Exception(str(e))
        else:
            self.pbkdf2(self.wordlist,self.password)

    def setHex(self,hexinput):
        self.hex = str(hexinput)
        if int(sys.version_info.major) == 2:
            self.hex = unicode(self.hex)
        self.hex = unicodedata.normalize('NFC',self.hex)
        self.hex = str(self.hex).replace("L","").replace("0x","")
        for char in self.hex:
            if char not in '0123456789abcdefABCDEF':
                self.hex = str("")
                raise TypeError("Input contains non-hex chars.")
                break
        if len(self.hex) % 2:
            self.hex = str("")
            raise Exception("Hex input is odd-length. Although many functions in this module auto-correct that, because of the high importance of not altering your Bip39 information, this error is thrown instead.  Please make sure the input hex is even number of hex chars, and in 8-char (4 byte) multiples, because Bip39 is specified for increments of 4 bytes.")
        try:
            self.test1 = binascii.unhexlify(self.hex)
            self.test2 = int(self.hex,16)
            self.test1, self.test2 = None, None
        except:
            self.hex = str("")
            raise TypeError("Input does not appear to be hex.")
        if len(self.hex) % 8:
            self.hex = str("")
            raise Exception("Input hex is not in 4-byte multiples (aka len(hexstr) % 8 != 0).  Bip39 works only in 4-byte multiples.")
        if len(self.hex) < 8:
            self.hex = str("")
            raise TypeError("Hex length too small.  Less than 32 bits of entropy not supported.")
        if len(self.hex) > 248:
            self.hex = str("")
            raise TypeError("Hex length too large.  Greater than 992 bits of entropy not supported.")
        try:
            self.wordlist = Bip39EngClass.hex_to_wordlist(self.hex)
            if self.wordlist and "  " in self.wordlist:
                self.wordlist = str(self.wordlist).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        except Exception as e:
            self.wordlist = str("")
            self.hex = str("")
            raise Exception(str(e))
        else:
            self.pbkdf2(self.wordlist,self.password)

    def pbkdf2(self,words,password=""):
        from pbkdf2 import PBKDF2 as kdf_
        self.words = str(words)
        self.password = str(password)
        self.presalt = 'mnemonic'
        if int(sys.version_info.major) == 2:
            self.words = unicode(self.words)
            self.password = unicode(self.password)
            self.presalt = unicode(self.presalt)
        self.words = unicodedata.normalize('NFC',self.words)
        if "  " in self.words:
            self.words = str(self.words).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        self.password = unicodedata.normalize('NFC',self.password)
        self.presalt = unicodedata.normalize('NFC',self.presalt)
        self.salt = str(self.presalt) + str(self.password)
        self.output = kdf_(self.words,self.salt,2048,macmodule=hmac,digestmodule=hashlib.sha512).read(64)
        self.bip32seed = hexlify_(self.output)
        assert len(self.bip32seed) == 128
        self.output, self.salt, self.presalt, self.words = None, None, None, None

    @staticmethod
    def wordlist_to_hex(wordlist):
        wordlist = str(wordlist)
        if int(sys.version_info.major) == 2:
            wordlist = unicode(wordlist)
        wordlist = unicodedata.normalize('NFC',wordlist)
        wordlist = str(wordlist).lower()
        if "  " in wordlist:
            wordlist = wordlist.replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        try:
            wordlistarray = str(wordlist).split(" ")
            if wordlistarray[0] == "":
                wordlistarray.pop(0)
        except:
            raise TypeError("Please make sure the input is a str of words, each separated by a single space, with no punctuation.")
        if len(wordlistarray) > 93:
            raise TypeError("Worldlist size too large.  Greater than 992 bits of entropy not supported.")
        if len(wordlistarray) < 3:
            raise TypeError("Worldlist size too small.  Less than 32 bits of entropy not supported.")
        if len(wordlistarray) % 3:
            raise TypeError("Worldlist has too many/few words.  Must be in 3-word multiples.  Wordlist is: " + str(wordlist) + ", and its list length appears to be " + str(len(wordlistarray)))
        for word in wordlistarray:
            if word not in Bip39EngClass.BIP0039_ENG_WORDLIST:
                raise TypeError("Word: '" + str(word) + "' is not in the BIP38 English wordlist. Check spelling maybe.")
        wordListIndexNumArray = []
        for i in range(len(wordlistarray)):
            wordListIndexNumArray.extend(' ')
            testWord = wordlistarray[i].replace(' ','')
            indexNum = Bip39EngClass.BIP0039_ENG_WORDLIST.index(testWord)
            wordListIndexNumArray[i] = indexNum
        wordListBinaryStr = str("")
        for i in range(len(wordListIndexNumArray)):
            newBinary = str(bin(int(wordListIndexNumArray[i])))
            if newBinary[:2] != "0b":
                raise Exception("Error converting wordlist into binary.")
            else:
                newBinary = newBinary[2:]
            for char in newBinary:
                if char not in '01':
                    raise Exception("Error (2) converting wordlist into binary.")
            if len(newBinary) < 11:
                for i in range(11 - len(newBinary)):
                    newBinary = "0" + newBinary
            if len(newBinary) > 11:
                raise Exception("Error (3) converting wordlist into binary.")
            assert len(newBinary) == 11
            wordListBinaryStr = wordListBinaryStr + str(newBinary)
        numberChecksumDigits = len(wordListBinaryStr) % 32
        binaryChecksum = wordListBinaryStr[(len(wordListBinaryStr) - numberChecksumDigits):]
        binaryNoCheck = wordListBinaryStr[:(-1*numberChecksumDigits)]
        hexoutput = hexlify_(int(binaryNoCheck,2))
        if len(hexoutput) % 8:
            for i in range(8 - (len(hexoutput) % 8)):
                hexoutput = "0" + hexoutput
        if len(hexoutput) < ((len(wordlistarray) // 3) * 8):
            for i in range(((len(wordlistarray) // 3) * 8) - len(hexoutput)):
                hexoutput = "0" + hexoutput
        assert not (len(hexoutput) % 2)
        checksum = sha256(hexoutput)
        checksumbinary = str(bin(int(checksum,16)))
        if checksumbinary[:2] != "0b":
            raise Exception("Error converting checksum into binary.")
        else:
            checksumbinary = checksumbinary[2:]
        for char in checksumbinary:
            if char not in '01':
                raise Exception("Error (2) converting checksum into binary.")
        if len(checksumbinary) < 256:
            for i in range(256 - len(checksumbinary)):
                checksumbinary = "0" + checksumbinary
        if len(checksumbinary) > 256:
            raise Exception("Error (3) converting checksum into binary.")
        assert len(checksumbinary) == 256 and 'b' not in checksumbinary
        if checksumbinary[:numberChecksumDigits] != binaryChecksum:
            raise Exception("Wordlist checksum didn't match.  Derived check: " + str(checksumbinary[:numberChecksumDigits]) + ", input check: " + str(binaryChecksum) + ", derived hex = " + str(hexoutput))
        else:
            return str(hexoutput)

    @staticmethod
    def hex_to_wordlist(hexinput):
        hexinput = str(hexinput)
        if int(sys.version_info.major) == 2:
            hexinput = unicode(hexinput)
        hexinput = unicodedata.normalize('NFC',hexinput)
        hexinput = str(hexinput).replace("L","").replace("0x","")
        for char in hexinput:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Input contains non-hex chars.")
        if len(hexinput) % 2:
            raise Exception("Hex input is odd-length. Although many functions in this module auto-correct that, because of the high importance of not altering your Bip39 information, this error is thrown instead.  Please make sure the input hex is even number of hex chars, and in 8-char (4 byte) multiples, because Bip39 is specified for increments of 4 bytes.")
        try:
            test1 = binascii.unhexlify(hexinput)
            test2 = int(hexinput,16)
            test1, test2 = None, None
        except:
            raise TypeError("Input does not appear to be hex.")
        if len(hexinput) % 8:
            raise Exception("Input hex is not in 4-byte multiples (aka len(hexstr) % 8 != 0).  Bip39 works only in 4-byte multiples.")
        if len(hexinput) < 8:
            raise TypeError("Hex length too small.  Less than 32 bits of entropy not supported.")
        if len(hexinput) > 248:
            raise TypeError("Hex length too large.  Greater than 992 bits of entropy not supported.")
        checksumlength = int((len(hexinput) * 4) // 32)
        checksum = sha256(hexinput)
        hexbinary = str(bin(int(hexinput,16)))
        if hexbinary[:2] != "0b":
            raise Exception("Error converting hex input into binary.")
        else:
            hexbinary = hexbinary[2:]
        if len(hexbinary) % 2:
            hexbinary = "0" + hexbinary
        for char in hexbinary:
            if char not in '01':
                raise Exception("Error (2) converting hex input into binary.")
        if len(hexbinary) < (len(hexinput) * 4):
            for i in range((len(hexinput) * 4) - len(hexbinary)):
                hexbinary = "0" + hexbinary
        assert not (len(hexbinary) % 32)
        checksumbinary = str(bin(int(checksum,16)))
        if checksumbinary[:2] != "0b":
            raise Exception("Error converting checksum into binary.")
        else:
            checksumbinary = checksumbinary[2:]
        for char in checksumbinary:
            if char not in '01':
                raise Exception("Error (2) converting checksum into binary.")
        if len(checksumbinary) < 256:
            for i in range(256 - len(checksumbinary)):
                checksumbinary = "0" + checksumbinary
        if len(checksumbinary) > 256:
            raise Exception("Error (3) converting checksum into binary.")
        assert len(checksumbinary) == 256
        finalbinstr = str(hexbinary) + str(checksumbinary)[:checksumlength]
        assert not (len(finalbinstr) % 11)
        wordBinArray = [finalbinstr[i:i+11] for i in range(0,len(finalbinstr),11)]
        wordListStr = str("")
        for i in range(len(wordBinArray)):
            wordListStr = wordListStr + str(Bip39EngClass.BIP0039_ENG_WORDLIST[int(wordBinArray[i],2)]) + str(" ")
        wordListStr = str(wordListStr).rstrip(" ")
        if "  " in wordListStr:
            wordListStr = str(wordListStr).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        return str(wordListStr)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
