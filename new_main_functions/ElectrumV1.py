#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *
from .bitcoin_funcs import *
from .misc_funcs_and_vars import *
from .CoinFromKey import *

class ElectrumWallet_V1(object):
    """
    >>> doctestwallet = ElectrumWallet_V1("f10bd6cb390f9ab686390433dcf66ec2")
    >>> doctestwallet.rootseed
    'f10bd6cb390f9ab686390433dcf66ec2'
    >>> doctestwallet.wordlist
    'forget gotten wise breath clear letter suppose jaw cast wheel midnight early'
    >>> doctestwallet.masterprivkey
    'bdef2e1b068cad476c3fa09ba5a936b0f0cfebf73a12b6abd20266c47af89899'
    >>> doctestwallet.masterpubkey
    '2321c4b46078b16702c4e05243f9e6b2fa93afffa35b988b28ef50fd5e6974cf0325b3df161e5aaffc7ba16398688e21d1ecbad3831ee954269db8fa775742af'
    >>> doctestwallet.get_privkey(0)
    '5e0e7a0c7ac46b1615d307ced23cb9a46e08125a40591dd11bcde29fe434b7fb'
    >>> doctestwallet.getpub(0)
    '040d47e6ce39d3fe6dd9eb1ca035bc1f88657652c37b38399093f4a156195ec676a76f860dd4e219da9d396f018da0de1fed8f00416f5012424f7411d2ca0dcca0'
    >>> ElectrumWallet_V1.get_pubkey("2321c4b46078b16702c4e05243f9e6b2fa93afffa35b988b28ef50fd5e6974cf0325b3df161e5aaffc7ba16398688e21d1ecbad3831ee954269db8fa775742af",0)
    '040d47e6ce39d3fe6dd9eb1ca035bc1f88657652c37b38399093f4a156195ec676a76f860dd4e219da9d396f018da0de1fed8f00416f5012424f7411d2ca0dcca0'
    >>> doctestwallet.get_privkey(0,True) # is change address
    'a0be1e12cd4baf242440d432702afcf145256152bdaaeb8d3b206204091ad5be'
    >>> ElectrumWallet_V1.get_pubkey("2321c4b46078b16702c4e05243f9e6b2fa93afffa35b988b28ef50fd5e6974cf0325b3df161e5aaffc7ba16398688e21d1ecbad3831ee954269db8fa775742af",0,True) # is change address
    '041db7c83ffa6489690b32fde54f2e1e7d88a9ffe8a180d22d16f5aeaed4ceb279e2462b47a62a76555778f968df2cf9aa39a299f9b93b6dc70c3013a4a4a00b4e'
    >>> doctestwallet2 = ElectrumWallet_V1("observe glare pocket left connect underneath further yours accept creak breast diamond")
    >>> doctestwallet2.rootseed
    'd3c1caa8325d861f0daa2989332b66ef'
    >>> doctestwallet2.wordlist
    'observe glare pocket left connect underneath further yours accept creak breast diamond'
    >>> doctestwallet2.masterprivkey
    'aff38177080ff7dce1b17bcf9cf6a0907301e3315640b6d13a7feabfdeca0b26'
    >>> doctestwallet2.masterpubkey
    'fdbd9042766aabb548f6982ce1f2f8c45892e3a07667a255aa4ab6499c82756613a43a88a979647157f39f8199a315c1d5c35c4c5f3bbc6d34b7b31ce0239208'
    >>> doctest3 = ElectrumWallet_V1("bbb4d6cb390f9ab686390433dcf66bbb")
    >>> doctest3.masterpubkey
    '41b1faff6281596e48f26f8cc1c28df16010bf5b85e937a3e606672b0911c6c4f363a0d08b09a7483ec132634eb9edd20fd1a20d50906040c704061661b95ef9'
    >>> doc4 = ElectrumWallet_V1("d0a240f3186f13bd502ebe5c3a416766")
    >>> doc4.wordlist
    'bang pale choose earth cool although loud voice favorite deserve after loud'
    >>> doc4.masterpubkey
    '5e8fd68a085de880f06f2a17b7f54fd70b60bafbbe1cd98422ddd5ae311b709f83110ecae740d4c4b3f6f32b9c43bfb5c4182418d3ac19e21929aa1bf99aaaf7'
    """

    ELECTRUM_ENG_V1_WORDLIST = [
         'like','just','love','know','never','want','time','out',
         'there','make','look','eye','down','only','think','heart',
         'back','then','into','about','more','away','still','them',
         'take','thing','even','through','long','always','world',
         'too','friend','tell','try','hand','thought','over','here',
         'other','need','smile','again','much','cry','been','night',
         'ever','little','said','end','some','those','around','mind',
         'people','girl','leave','dream','left','turn','myself',
         'give','nothing','really','off','before','something','find',
         'walk','wish','good','once','place','ask','stop','keep',
         'watch','seem','everything','wait','got','yet','made',
         'remember','start','alone','run','hope','maybe','believe',
         'body','hate','after','close','talk','stand','own','each',
         'hurt','help','home','god','soul','new','many','two',
         'inside','should','true','first','fear','mean','better',
         'play','another','gone','change','use','wonder','someone',
         'hair','cold','open','best','any','behind','happen','water',
         'dark','laugh','stay','forever','name','work','show','sky',
         'break','came','deep','door','put','black','together',
         'upon','happy','such','great','white','matter','fill',
         'past','please','burn','cause','enough','touch','moment',
         'soon','voice','scream','anything','stare','sound','red',
         'everyone','hide','kiss','truth','death','beautiful','mine',
         'blood','broken','very','pass','next','forget','tree',
         'wrong','air','mother','understand','lip','hit','wall',
         'memory','sleep','free','high','realize','school','might',
         'skin','sweet','perfect','blue','kill','breath','dance',
         'against','fly','between','grow','strong','under','listen',
         'bring','sometimes','speak','pull','person','become',
         'family','begin','ground','real','small','father','sure',
         'feet','rest','young','finally','land','across','today',
         'different','guy','line','fire','reason','reach','second',
         'slowly','write','eat','smell','mouth','step','learn',
         'three','floor','promise','breathe','darkness','push',
         'earth','guess','save','song','above','along','both',
         'color','house','almost','sorry','anymore','brother','okay',
         'dear','game','fade','already','apart','warm','beauty',
         'heard','notice','question','shine','began','piece','whole',
         'shadow','secret','street','within','finger','point',
         'morning','whisper','child','moon','green','story','glass',
         'kid','silence','since','soft','yourself','empty','shall',
         'angel','answer','baby','bright','dad','path','worry',
         'hour','drop','follow','power','war','half','flow','heaven',
         'act','chance','fact','least','tired','children','near',
         'quite','afraid','rise','sea','taste','window','cover',
         'nice','trust','lot','sad','cool','force','peace','return',
         'blind','easy','ready','roll','rose','drive','held','music',
         'beneath','hang','mom','paint','emotion','quiet','clear',
         'cloud','few','pretty','bird','outside','paper','picture',
         'front','rock','simple','anyone','meant','reality','road',
         'sense','waste','bit','leaf','thank','happiness','meet',
         'men','smoke','truly','decide','self','age','book','form',
         'alive','carry','escape','damn','instead','able','ice',
         'minute','throw','catch','leg','ring','course','goodbye',
         'lead','poem','sick','corner','desire','known','problem',
         'remind','shoulder','suppose','toward','wave','drink',
         'jump','woman','pretend','sister','week','human','joy',
         'crack','grey','pray','surprise','dry','knee','less',
         'search','bleed','caught','clean','embrace','future','king',
         'son','sorrow','chest','hug','remain','sat','worth','blow',
         'daddy','final','parent','tight','also','create','lonely',
         'safe','cross','dress','evil','silent','bone','fate',
         'perhaps','anger','class','scar','snow','tiny','tonight',
         'continue','control','dog','edge','mirror','month',
         'suddenly','comfort','given','loud','quickly','gaze','plan',
         'rush','stone','town','battle','ignore','spirit','stood',
         'stupid','yours','brown','build','dust','hey','kept','pay',
         'phone','twist','although','ball','beyond','hidden','nose',
         'taken','fail','float','pure','somehow','wash','wrap',
         'angry','cheek','creature','forgotten','heat','rip',
         'single','space','special','weak','whatever','yell',
         'anyway','blame','job','choose','country','curse','drift',
         'echo','figure','grew','laughter','neck','suffer','worse',
         'yeah','disappear','foot','forward','knife','mess',
         'somewhere','stomach','storm','beg','idea','lift','offer',
         'breeze','field','five','often','simply','stuck','win',
         'allow','confuse','enjoy','except','flower','seek',
         'strength','calm','grin','gun','heavy','hill','large',
         'ocean','shoe','sigh','straight','summer','tongue','accept',
         'crazy','everyday','exist','grass','mistake','sent','shut',
         'surround','table','ache','brain','destroy','heal','nature',
         'shout','sign','stain','choice','doubt','glance','glow',
         'mountain','queen','stranger','throat','tomorrow','city',
         'either','fish','flame','rather','shape','spin','spread',
         'ash','distance','finish','image','imagine','important',
         'nobody','shatter','warmth','became','feed','flesh','funny',
         'lust','shirt','trouble','yellow','attention','bare','bite',
         'money','protect','amaze','appear','born','choke',
         'completely','daughter','fresh','friendship','gentle',
         'probably','six','deserve','expect','grab','middle',
         'nightmare','river','thousand','weight','worst','wound',
         'barely','bottle','cream','regret','relationship','stick',
         'test','crush','endless','fault','itself','rule','spill',
         'art','circle','join','kick','mask','master','passion',
         'quick','raise','smooth','unless','wander','actually',
         'broke','chair','deal','favorite','gift','note','number',
         'sweat','box','chill','clothes','lady','mark','park','poor',
         'sadness','tie','animal','belong','brush','consume','dawn',
         'forest','innocent','pen','pride','stream','thick','clay',
         'complete','count','draw','faith','press','silver',
         'struggle','surface','taught','teach','wet','bless','chase',
         'climb','enter','letter','melt','metal','movie','stretch',
         'swing','vision','wife','beside','crash','forgot','guide',
         'haunt','joke','knock','plant','pour','prove','reveal',
         'steal','stuff','trip','wood','wrist','bother','bottom',
         'crawl','crowd','fix','forgive','frown','grace','loose',
         'lucky','party','release','surely','survive','teacher',
         'gently','grip','speed','suicide','travel','treat','vein',
         'written','cage','chain','conversation','date','enemy',
         'however','interest','million','page','pink','proud','sway',
         'themselves','winter','church','cruel','cup','demon',
         'experience','freedom','pair','pop','purpose','respect',
         'shoot','softly','state','strange','bar','birth','curl',
         'dirt','excuse','lord','lovely','monster','order','pack',
         'pants','pool','scene','seven','shame','slide','ugly',
         'among','blade','blonde','closet','creek','deny','drug',
         'eternity','gain','grade','handle','key','linger','pale',
         'prepare','swallow','swim','tremble','wheel','won','cast',
         'cigarette','claim','college','direction','dirty','gather',
         'ghost','hundred','loss','lung','orange','present','swear',
         'swirl','twice','wild','bitter','blanket','doctor',
         'everywhere','flash','grown','knowledge','numb','pressure',
         'radio','repeat','ruin','spend','unknown','buy','clock',
         'devil','early','false','fantasy','pound','precious',
         'refuse','sheet','teeth','welcome','add','ahead','block',
         'bury','caress','content','depth','despite','distant',
         'marry','purple','threw','whenever','bomb','dull','easily',
         'grasp','hospital','innocence','normal','receive','reply',
         'rhyme','shade','someday','sword','toe','visit','asleep',
         'bought','center','consider','flat','hero','history','ink',
         'insane','muscle','mystery','pocket','reflection','shove',
         'silently','smart','soldier','spot','stress','train','type',
         'view','whether','bus','energy','explain','holy','hunger',
         'inch','magic','mix','noise','nowhere','prayer','presence',
         'shock','snap','spider','study','thunder','trail','admit',
         'agree','bag','bang','bound','butterfly','cute','exactly',
         'explode','familiar','fold','further','pierce','reflect',
         'scent','selfish','sharp','sink','spring','stumble',
         'universe','weep','women','wonderful','action','ancient',
         'attempt','avoid','birthday','branch','chocolate','core',
         'depress','drunk','especially','focus','fruit','honest',
         'match','palm','perfectly','pillow','pity','poison','roar',
         'shift','slightly','thump','truck','tune','twenty','unable',
         'wipe','wrote','coat','constant','dinner','drove','egg',
         'eternal','flight','flood','frame','freak','gasp','glad',
         'hollow','motion','peer','plastic','root','screen','season',
         'sting','strike','team','unlike','victim','volume','warn',
         'weird','attack','await','awake','built','charm','crave',
         'despair','fought','grant','grief','horse','limit',
         'message','ripple','sanity','scatter','serve','split',
         'string','trick','annoy','blur','boat','brave','clearly',
         'cling','connect','fist','forth','imagination','iron',
         'jock','judge','lesson','milk','misery','nail','naked',
         'ourselves','poet','possible','princess','sail','size',
         'snake','society','stroke','torture','toss','trace','wise',
         'bloom','bullet','cell','check','cost','darling','during',
         'footstep','fragile','hallway','hardly','horizon',
         'invisible','journey','midnight','mud','nod','pause',
         'relax','shiver','sudden','value','youth','abuse','admire',
         'blink','breast','bruise','constantly','couple','creep',
         'curve','difference','dumb','emptiness','gotta','honor',
         'plain','planet','recall','rub','ship','slam','soar',
         'somebody','tightly','weather','adore','approach','bond',
         'bread','burst','candle','coffee','cousin','crime','desert',
         'flutter','frozen','grand','heel','hello','language',
         'level','movement','pleasure','powerful','random','rhythm',
         'settle','silly','slap','sort','spoken','steel','threaten',
         'tumble','upset','aside','awkward','bee','blank','board',
         'button','card','carefully','complain','crap','deeply',
         'discover','drag','dread','effort','entire','fairy','giant',
         'gotten','greet','illusion','jeans','leap','liquid','march',
         'mend','nervous','nine','replace','rope','spine','stole',
         'terror','accident','apple','balance','boom','childhood',
         'collect','demand','depression','eventually','faint',
         'glare','goal','group','honey','kitchen','laid','limb',
         'machine','mere','mold','murder','nerve','painful','poetry',
         'prince','rabbit','shelter','shore','shower','soothe',
         'stair','steady','sunlight','tangle','tease','treasure',
         'uncle','begun','bliss','canvas','cheer','claw','clutch',
         'commit','crimson','crystal','delight','doll','existence',
         'express','fog','football','gay','goose','guard','hatred',
         'illuminate','mass','math','mourn','rich','rough','skip',
         'stir','student','style','support','thorn','tough','yard',
         'yearn','yesterday','advice','appreciate','autumn','bank',
         'beam','bowl','capture','carve','collapse','confusion',
         'creation','dove','feather','girlfriend','glory',
         'government','harsh','hop','inner','loser','moonlight',
         'neighbor','neither','peach','pig','praise','screw',
         'shield','shimmer','sneak','stab','subject','throughout',
         'thrown','tower','twirl','wow','army','arrive','bathroom',
         'bump','cease','cookie','couch','courage','dim','guilt',
         'howl','hum','husband','insult','led','lunch','mock',
         'mostly','natural','nearly','needle','nerd','peaceful',
         'perfection','pile','price','remove','roam','sanctuary',
         'serious','shiny','shook','sob','stolen','tap','vain',
         'void','warrior','wrinkle','affection','apologize',
         'blossom','bounce','bridge','cheap','crumble','decision',
         'descend','desperately','dig','dot','flip','frighten',
         'heartbeat','huge','lazy','lick','odd','opinion','process',
         'puzzle','quietly','retreat','score','sentence','separate',
         'situation','skill','soak','square','stray','taint','task',
         'tide','underneath','veil','whistle','anywhere','bedroom',
         'bid','bloody','burden','careful','compare','concern',
         'curtain','decay','defeat','describe','double','dreamer',
         'driver','dwell','evening','flare','flicker','grandma',
         'guitar','harm','horrible','hungry','indeed','lace',
         'melody','monkey','nation','object','obviously','rainbow',
         'salt','scratch','shown','shy','stage','stun','third',
         'tickle','useless','weakness','worship','worthless',
         'afternoon','beard','boyfriend','bubble','busy','certain',
         'chin','concrete','desk','diamond','doom','drawn','due',
         'felicity','freeze','frost','garden','glide','harmony',
         'hopefully','hunt','jealous','lightning','mama','mercy',
         'peel','physical','position','pulse','punch','quit','rant',
         'respond','salty','sane','satisfy','savior','sheep','slept',
         'social','sport','tuck','utter','valley','wolf','aim',
         'alas','alter','arrow','awaken','beaten','belief','brand',
         'ceiling','cheese','clue','confidence','connection','daily',
         'disguise','eager','erase','essence','everytime',
         'expression','fan','flag','flirt','foul','fur','giggle',
         'glorious','ignorance','law','lifeless','measure','mighty',
         'muse','north','opposite','paradise','patience','patient',
         'pencil','petal','plate','ponder','possibly','practice',
         'slice','spell','stock','strife','strip','suffocate','suit',
         'tender','tool','trade','velvet','verse','waist','witch',
         'aunt','bench','bold','cap','certainly','click','companion',
         'creator','dart','delicate','determine','dish','dragon',
         'drama','drum','dude','everybody','feast','forehead',
         'former','fright','fully','gas','hook','hurl','invite',
         'juice','manage','moral','possess','raw','rebel','royal',
         'scale','scary','several','slight','stubborn','swell',
         'talent','tea','terrible','thread','torment','trickle',
         'usually','vast','violence','weave','acid','agony',
         'ashamed','awe','belly','blend','blush','character','cheat',
         'common','company','coward','creak','danger','deadly',
         'defense','define','depend','desperate','destination','dew',
         'duck','dusty','embarrass','engine','example','explore',
         'foe','freely','frustrate','generation','glove','guilty',
         'health','hurry','idiot','impossible','inhale','jaw',
         'kingdom','mention','mist','moan','mumble','mutter',
         'observe','ode','pathetic','pattern','pie','prefer','puff',
         'rape','rare','revenge','rude','scrape','spiral','squeeze',
         'strain','sunset','suspend','sympathy','thigh','throne',
         'total','unseen','weapon','weary']

    # NUMBER_OF_WORDS = len(ELECTRUM_ENG_V1_WORDLIST)
    NUMBER_OF_WORDS = 1626

    def __init__(self,unknowninput):
        super(ElectrumWallet_V1,self).__init__()
        self.unknowninput = unknowninput
        try:
            self.rootseed = ElectrumWallet_V1.wordlist_to_hex(self.unknowninput)
        except Exception as e:
            try:
                self.wordlist = ElectrumWallet_V1.hex_to_wordlist(self.unknowninput)
            except Exception as f:
                raise Exception("Input must be hex (exactly 32 hex chars) or 12 lowercase words with exactly one space between them.  Attempt to treat input as wordlist threw exception: '" + str(e) + "', and attempt to treat input as hex threw exception: '" + str(f) + "'.")
            else:
                self.rootseed = str(self.unknowninput)
        else:
            self.wordlist = str(self.unknowninput)
        self.unknowninput = None
        # Electrum key stretch does a hexlify on the hex, so the resulting hex chars are always in '0123456789'
        # Therefore I can do the quick and dirty replace("b'","") on Python 3's binary b'str' indicator without fear
        self.unchanged = str(str(binascii.hexlify(self.rootseed.encode('utf-8'))).replace("b'","").replace("'",""))
        self.masterprivkey = str(str(binascii.hexlify(self.rootseed.encode('utf-8'))).replace("b'","").replace("'",""))
        for i in range(100000):
            self.masterprivkey = hashlib.sha256(binascii.unhexlify(str(self.masterprivkey) + str(self.unchanged))).hexdigest()
        self.masterprivkey = hexlify_(self.masterprivkey)
        self.unchanged = None
        self.masterpubkey = str(privkey_to_pubkey(self.masterprivkey,False)[2:])

    def __str__(self):
        return self.wordlist

    def get_privkey(self,index,isChange=False):
        try:
            index = int(index)
        except:
            raise TypeError("Input must be an integer index number")
        if isChange:
            indexStr = str(str(index) + ":" + str("1") + ":")
        else:
            indexStr = str(str(index) + ":" + str("0") + ":")
        try:
            indexBytes = bytes(indexStr)
        except:
            indexBytes = bytes(indexStr,'utf-8')
        offset = double_sha256(hexlify_(indexBytes) + self.masterpubkey)
        return add_privkeys(offset,self.masterprivkey)

    def getpub(self,index,isChange=False):
        return ElectrumWallet_V1.get_pubkey(self.masterpubkey,index,isChange)

    @staticmethod
    def get_pubkey(masterpubkey,index,isChange=False):
        try:
            test1 = binascii.unhexlify(masterpubkey)
            test2 = int(masterpubkey,16)
            test1, test1 = None, None
        except:
            raise TypeError("First input must be a hex master public key")
        if len(masterpubkey) == 130:
            masterpubkey = masterpubkey[2:]
        elif len(masterpubkey) == 66:
            masterpubkey = str(uncompress_pubkey(masterpubkey))[2:]
        assert len(masterpubkey) == 128
        try:
            index = int(index)
        except:
            raise TypeError("Second input must be an integer index number")
        if isChange:
            indexStr = str(str(index) + ":" + str("1") + ":")
        else:
            indexStr = str(str(index) + ":" + str("0") + ":")
        try:
            indexBytes = bytes(indexStr)
        except:
            indexBytes = bytes(indexStr,'utf-8')
        offset = privkey_to_pubkey(double_sha256(hexlify_(indexBytes) + masterpubkey))
        masterpubkey = str("04" + masterpubkey) 
        return add_pubkeys(offset,masterpubkey,False)

    @staticmethod
    def hex_to_wordlist(hexinput):
        """
        Convert hex input to Electrum version 1 nmemonic word list (12 words)

        >>> ElectrumWallet_V1.hex_to_wordlist("0000000000000000000000007794c0ac")
        'like like like like like like like like like blame young truck'
        >>> ElectrumWallet_V1.hex_to_wordlist("f10bd6cb390f9ab686390433dcf66ec2")
        'forget gotten wise breath clear letter suppose jaw cast wheel midnight early'
        """

        hexinput = str(hexinput)
        if int(sys.version_info.major) == 2:
            hexinput = unicode(hexinput)
        hexinput = unicodedata.normalize('NFC',hexinput)
        hexinput = str(hexinput).replace("L","").replace("0x","")
        for char in hexinput:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Input contains non-hex chars.")
        if len(hexinput) % 2:
            raise Exception("Hex input is odd-length. Although many functions in this module auto-correct that, because of the high importance of not altering your Electrum seed, this error is thrown instead.  Please make sure the input hex is exactly 32 hex chars.")
        try:
            test1 = binascii.unhexlify(hexinput)
            test2 = int(hexinput,16)
            test1, test2 = None, None
        except:
            raise TypeError("Input does not appear to be hex.")
        assert len(hexinput) == 32
        output = []
        for i in range(int(len(hexinput) // 8)):
            word = hexinput[8*i:8*i+8]
            x = int(word,16)
            w1 = (x % ElectrumWallet_V1.NUMBER_OF_WORDS)
            w2 = ((x // ElectrumWallet_V1.NUMBER_OF_WORDS) + w1) % ElectrumWallet_V1.NUMBER_OF_WORDS
            w3 = ((x // ElectrumWallet_V1.NUMBER_OF_WORDS // ElectrumWallet_V1.NUMBER_OF_WORDS) + w2) % ElectrumWallet_V1.NUMBER_OF_WORDS
            output += [ ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST[w1], ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST[w2], ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST[w3] ]
        return str(str(output).replace(",","").replace("[ ","").replace(" ]","").replace("[","").replace("]","").replace("u'","").replace("'",""))

    @staticmethod
    def wordlist_to_hex(wlist):
        """
        Convert Electrum version 1 nmemonic wordlist to hex

        >>> ElectrumWallet_V1.wordlist_to_hex("forget gotten wise breath clear letter suppose jaw cast wheel midnight early")
        'f10bd6cb390f9ab686390433dcf66ec2'
        >>> ElectrumWallet_V1.wordlist_to_hex("like like like like like like like like like blame young truck")
        '0000000000000000000000007794c0ac'
        """

        wlist = str(wlist)
        if int(sys.version_info.major) == 2:
            wlist = unicode(wlist)
        wlist = unicodedata.normalize('NFC',wlist)
        wlist = str(wlist).lower()
        if "  " in wlist:
            wlist = wlist.replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        try:
            wordlistarray = str(wlist).split(" ")
            if wordlistarray[0] == "":
                wordlistarray.pop(0)
        except:
            raise TypeError("Please make sure the input is a str of words, each separated by a single space, with no punctuation.")
        if len(wordlistarray) != 12:
            raise TypeError("Electrum version 1 word lists are exactly 12 words long, your list has a length of " + str(len(wordlistarray)))
        for word in wordlistarray:
            if word not in ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST:
                raise TypeError("Word: '" + str(word) + "' is not in the Electrum V1 wordlist. Check spelling maybe.")
        wlist = str(wlist).replace("\n","").replace("\r","")
        wlist = wlist.split()
        output = ''
        for i in range(int(len(wlist) // 3)):
            word1, word2, word3 = wlist[3*i:3*i+3]
            w1 = ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST.index(word1)
            w2 = (ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST.index(word2)) % ElectrumWallet_V1.NUMBER_OF_WORDS
            w3 = (ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST.index(word3)) % ElectrumWallet_V1.NUMBER_OF_WORDS
            x = w1 + ElectrumWallet_V1.NUMBER_OF_WORDS*((w2-w1) % ElectrumWallet_V1.NUMBER_OF_WORDS) + ElectrumWallet_V1.NUMBER_OF_WORDS*ElectrumWallet_V1.NUMBER_OF_WORDS*((w3-w2) % ElectrumWallet_V1.NUMBER_OF_WORDS)
            output += '%08x'%x
        output = hexlify_(binascii.unhexlify(output))
        assert len(output) == 32
        return str(output)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
