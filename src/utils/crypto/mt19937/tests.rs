use super::*;

#[test]
fn mersenne_gen_32_rand() {
    let mut mt = MT19937::new(1);
    let mut rands = Vec::new();
    for _i in 0..1000 {
        let v = mt.gen_rand();
        rands.push(v);
    }
    let ref_vals = vec![ 1791095845, 4282876139, 3093770124, 4005303368, 491263, 550290313, 1298508491, 4290846341, 630311759, 1013994432, 396591248, 1703301249, 799981516, 1666063943, 1484172013, 2876537340, 1704103302, 4018109721, 2314200242, 3634877716, 1800426750, 1345499493, 2942995346, 2252917204, 878115723, 1904615676, 3771485674, 986026652, 117628829, 2295290254, 2879636018, 3925436996, 1792310487, 1963679703, 2399554537, 1849836273, 602957303, 4033523166, 850839392, 3343156310, 3439171725, 3075069929, 4158651785, 3447817223, 1346146623, 398576445, 2973502998, 2225448249, 3764062721, 3715233664, 3842306364, 3561158865, 365262088, 3563119320, 167739021, 1172740723, 729416111, 254447594, 3771593337, 2879896008, 422396446, 2547196999, 1808643459, 2884732358, 4114104213, 1768615473, 2289927481, 848474627, 2971589572, 1243949848, 1355129329, 610401323, 2948499020, 3364310042, 3584689972, 1771840848, 78547565, 146764659, 3221845289, 2680188370, 4247126031, 2837408832, 3213347012, 1282027545, 1204497775, 1916133090, 3389928919, 954017671, 443352346, 315096729, 1923688040, 2015364118, 3902387977, 413056707, 1261063143, 3879945342, 1235985687, 513207677, 558468452, 2253996187, 83180453, 359158073, 2915576403, 3937889446, 908935816, 3910346016, 1140514210, 1283895050, 2111290647, 2509932175, 229190383, 2430573655, 2465816345, 2636844999, 630194419, 4108289372, 2531048010, 1120896190, 3005439278, 992203680, 439523032, 2291143831, 1778356919, 4079953217, 2982425969, 2117674829, 1778886403, 2321861504, 214548472, 3287733501, 2301657549, 194758406, 2850976308, 601149909, 2211431878, 3403347458, 4057003596, 127995867, 2519234709, 3792995019, 3880081671, 2322667597, 590449352, 1924060235, 598187340, 3831694379, 3467719188, 1621712414, 1708008996, 2312516455, 710190855, 2801602349, 3983619012, 1551604281, 1493642992, 2452463100, 3224713426, 2739486816, 3118137613, 542518282, 3793770775, 2964406140, 2678651729, 2782062471, 3225273209, 1520156824, 1498506954, 3278061020, 1159331476, 1531292064, 3847801996, 3233201345, 1838637662, 3785334332, 4143956457, 50118808, 2849459538, 2139362163, 2670162785, 316934274, 492830188, 3379930844, 4078025319, 275167074, 1932357898, 1526046390, 2484164448, 4045158889, 1752934226, 1631242710, 1018023110, 3276716738, 3879985479, 3313975271, 2463934640, 1294333494, 12327951, 3318889349, 2650617233, 656828586, 1402929172, 2485213814, 2263697328, 38689046, 3805092325, 3045314445, 1534461937, 2021386866, 3902128737, 3283900085, 2677311316, 2007436298, 67951712, 1155350711, 3991902525, 3572092472, 2967379673, 2367922581, 4283469031, 300997728, 740196857, 2029264851, 588993561, 3190150641, 4005467022, 824445069, 2992811220, 1994202740, 283468587, 989400710, 3244689101, 2182906552, 3237873595, 895794063, 3964360216, 211760123, 3055975561, 2228494786, 533739719, 739929909, 85384517, 1702152612, 112575333, 461130488, 121575445, 2189618472, 1057468493, 438667483, 3693791921, 1240033649, 2314261807, 995395021, 2374352296, 4156102094, 3616495149, 1195370327, 533320336, 1003401116, 1199084778, 393231917, 2515816899, 2448417652, 4164382018, 1794980814, 2409606446, 1579874688, 80089501, 3491786815, 3438691147, 1244509731, 1000616885, 3081173469, 3466490401, 2632592002, 1665848788, 1833563731, 3708884016, 3229269814, 3208863008, 1837441277, 2389033628, 1839888439, 586070738, 1554367775, 257344540, 658583774, 521166154, 4025201800, 191348845, 3935950435, 461683744, 3358486024, 969414228, 2647112653, 3062264370, 154616399, 2403966121, 2810299200, 53927532, 557356243, 309127192, 1264264305, 4154420202, 1549687572, 2439972908, 1179591951, 873137822, 317694427, 1083730830, 653424115, 3194707731, 694146299, 839363226, 4031736043, 2496917590, 1594007943, 4166204131, 214826037, 3637101999, 3182379886, 1030138300, 1282821875, 2120724770, 877711460, 2662689508, 4216612640, 3560445843, 3835496899, 673413912, 3261378259, 79784165, 2796541534, 300742822, 170439343, 2088836327, 3495572357, 2604165199, 3275226687, 2443198321, 1955423319, 1363061152, 2284177194, 4246074058, 469594818, 2489986776, 627205858, 1632693918, 2185230993, 2366304580, 926210880, 3201187004, 3936095732, 2874333390, 1984929937, 1137820839, 568083619, 284905937, 3282392732, 1589499542, 913684262, 2704616105, 318937546, 902690509, 409822534, 3233060505, 696667366, 285772016, 1530999856, 1118044850, 409343934, 3456394540, 615309929, 830793910, 3998670080, 2746463574, 2476410359, 2253441808, 3606248723, 3972019977, 2677019248, 1130851036, 1393792051, 283300719, 3126786186, 3157084283, 2245136708, 3316479383, 3164581134, 3899039423, 710413845, 4002789550, 2950892924, 59921539, 1833138616, 1006577496, 3129130192, 2649042862, 3248435766, 4075994063, 1707727431, 4080975356, 3973704206, 2390807245, 874070159, 3932499353, 34371381, 2755505876, 3978646009, 1675070394, 1264917461, 2087314034, 717051630, 2595493789, 103515692, 2360290341, 1941332118, 3977918939, 3471788470, 3945930060, 1582166540, 1695977848, 2616524091, 4137181082, 149669836, 747133895, 1522897623, 542581159, 337240701, 580160555, 2977207756, 2171802482, 54600486, 92448347, 1973731952, 4071501053, 4128826181, 3552433890, 1435314593, 64506027, 2027582874, 756757176, 452651973, 1426202185, 2160694580, 562627161, 3804008987, 3476736043, 2295133185, 1480632658, 1208933503, 4037730910, 1522929632, 2499731866, 3849494356, 3774554654, 1037187943, 3628106816, 102581398, 3888630370, 4147765044, 1975170691, 1846698054, 2346541708, 1487297831, 3429976294, 2478486611, 1227153135, 543425712, 2105622845, 4080404934, 2573159181, 1346948260, 66714903, 4092378518, 2548983234, 937991802, 1862625756, 1068159225, 3467587050, 3710000479, 1353966133, 1010469769, 3834927785, 3500828089, 2481877848, 2336020845, 790317814, 821456605, 3384130292, 2529048268, 2628653906, 206745962, 231538571, 68173929, 1804718116, 213507184, 2916578448, 1715475614, 3945364595, 2477783658, 1726676, 3725959097, 4195148579, 3376541097, 1617400145, 1093939970, 4182368469, 353282141, 2597235876, 677556845, 3559865646, 899765072, 2468367131, 1792645448, 2697566748, 1493317250, 1226540771, 3005979021, 2520429993, 2995780473, 3221318948, 320936676, 3686429864, 156636178, 3243053281, 3390446502, 2998133055, 3867740659, 3712910894, 20028776, 1385904345, 1134744551, 2881015920, 2007370239, 1936488805, 1545398786, 1641118818, 1031726876, 1764421326, 99508939, 1724341690, 2283497130, 1363153690, 559182056, 2671123349, 2411447866, 1847897983, 720827792, 4182448092, 1808502309, 2911132649, 2940712173, 852851176, 1176392938, 1832666891, 42948502, 1474660870, 944318560, 3425832590, 137250916, 3779563863, 4015245515, 3881971619, 3359059647, 2846359931, 2223049248, 1160535662, 70707035, 1083906737, 1283337190, 3671758714, 2322372736, 2266517142, 3693171809, 3445255622, 795059876, 2458819474, 358828827, 3148823196, 190148069, 2229137972, 1906140774, 3310921202, 82973406, 2443226489, 287900466, 2000208686, 3486532103, 1471837653, 2732847376, 292956903, 3319367325, 1623171979, 3030881725, 341991419, 1023108090, 4221167374, 190773608, 780021278, 1207817352, 3486906536, 3715531696, 3757931678, 314062231, 2956712386, 2836103900, 2445959872, 804784871, 691367052, 2243203729, 2005234426, 3882131873, 1482502666, 2040765468, 966539241, 3637933003, 2544819077, 3602530129, 1341188741, 598203257, 3935502378, 2320590422, 3906854836, 2006116153, 1104314680, 939235918, 476274519, 1893343226, 828768629, 2062779089, 2145697674, 1431445192, 3129251632, 38279669, 894188307, 2170951052, 1065296025, 2891145549, 3657902864, 238195972, 1786056664, 676799350, 2648642203, 2598898610, 1003588420, 1371055747, 437946042, 3824741900, 2215588994, 3394628428, 2049304928, 934152032, 655719741, 859891087, 2670637412, 2922467834, 2336505674, 670946188, 2809498514, 2191983774, 620818363, 4243705477, 3227787408, 621447007, 953693792, 207446972, 2230599083, 3861450476, 3372820767, 3072317163, 95908451, 1332847916, 1393126168, 1687665598, 3749173071, 346963477, 3628000147, 1512349517, 2312584737, 4352004, 3722054183, 2682767484, 4079385667, 860159138, 3549391010, 2684833834, 3668397902, 1380625106, 424099686, 203230246, 2797330810, 3106827952, 3021582458, 3260962513, 2620964350, 1745063685, 3434321402, 3025095910, 148482267, 2514098677, 3308150152, 4164247848, 3142750405, 1305147909, 1115396103, 1347569102, 1104104229, 972645225, 2715722062, 2887654945, 1483041307, 3345445555, 3421322317, 2201865246, 1916183467, 2642542766, 3361883145, 196113219, 4254043907, 1915982787, 1289556790, 4157582689, 614205375, 1544299747, 3871090256, 2379549980, 2325979813, 1766753728, 4186477989, 4149138397, 2734195090, 872126798, 4268823911, 4264157638, 2345356252, 2831242292, 2260982154, 3474960288, 581658414, 1967743039, 1527742075, 3810959069, 112607890, 2293230500, 688892061, 2479396344, 3202487335, 3940625180, 130565686, 1349249053, 1574290615, 3118740839, 3703748954, 3458461595, 2975028156, 2061854570, 2967573900, 2094115985, 810188871, 3613828699, 1897964423, 2385972604, 2497855955, 1159131320, 4250951219, 2090544032, 875770572, 1184749118, 1064004710, 968044723, 1126024800, 2777786910, 3221965974, 3956238597, 1962694107, 861032543, 244510057, 3778940310, 2184060620, 2000628852, 910361965, 3113765910, 3429979110, 1300822418, 1277028573, 2100270365, 118566930, 874774580, 2548772986, 380603935, 3624267057, 711631586, 1636451795, 2160353657, 3220616925, 3382634669, 2195335915, 3880940467, 2323370326, 942848783, 4120739015, 3170248368, 3452985756, 1107254995, 138826523, 2423258109, 3046795051, 568780947, 1997166159, 1598104390, 4069691736, 355861498, 951046358, 2172077579, 1147065573, 2982454721, 349928029, 1962705167, 1840903859, 1551663074, 468232022, 3504725549, 2722093427, 196758975, 3448700842, 1665707670, 2992735341, 1969342055, 3290852818, 3159945384, 1470829228, 3906860944, 3632904465, 1191447403, 1841547864, 3512288486, 3539095424, 2818855152, 2690780513, 48448594, 615997303, 3158320071, 336669172, 2591989774, 78738084, 2920659994, 286581664, 2508088193, 1969602480, 2463253848, 486799861, 1550558230, 119328546, 4117584734, 3242105365, 4238887108, 1695869891, 1662734000, 3208076406, 3591365778, 1943063905, 4218269323, 1933107851, 2514071929, 2053305780, 2881631052, 2035831364, 370469037, 3449560256, 4258247769, 1728262696, 3347927815, 3885597447, 4270764278, 159175969, 2807576122, 3323764999, 160751778, 539625604, 3088465285, 2656495549, 2955436150, 44514151, 2614832306, 2313386572, 456173997, 12962046, 1205532000, 4085346197, 3333816434, 3888672125, 3823235164, 3418651975, 2193007324, 3931073263, 3073942169, 625167849, 334057719, 677445473, 2642711553, 805871885, 3598340212, 2673599526, 2989320405, 3890422171, 2383961766, 4251825108, 3698781345, 3054247681, 3201131518, 3143058847, 1136230645, 3905384561, 4293975666, 1721739558, 2464159772, 1073100491, 2744737394, 744876899, 2103243807, 513064115, 3819835458, 3490135875, 3755992992, 630468426, 3641230240, 1135149025, 2781952773, 3517961216, 2515041189, 1333962094, 1209388872, 4219450795, 4259121516, 1145204504, 3434518672, 2292023677, 2154511200, 1350625504, 3317069097, 3911739544, 533778709, 1574348793, 3955741595, 1862264878, 192571683, 2200280382, 981850180, 4032486718, 3618451325, 132924960, 1312420089, 3078970413, 2080145240, 3826897254, 2791958899, 117197738, 618229817, 2242193049, 1313393440, 1400115560, 3809294369, 3691478518, 3808957062, 2398810305, 2212838707, 2964506143, 1147132295, 1944990971, 3781046413, 2698566783, 2138822019, 1245956508, 1432110735, 40151837, 3842692674, 2477147887, 878247997, 1337642707, 3520175200, 2221647418, 3602781138, 3935933160, 2245391866, 1831695266, 695517982, 1062557881, 4075825248, 1594694577, 255331836, 4002313006, 3807486291, 4023819049, 2466789652, 3626369528, 1627135016, 3952256888, 2752667134, 978824302, 548926898 ];

    assert_eq!(rands, ref_vals);
}