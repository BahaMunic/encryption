**وصف الشفرة / شرح المزايا**

هذا البرنامج هو تطبيق يستخدم تقنيات التشفير المتقدمة لحماية الملفات والمعلومات باستخدام خوارزمية AES ضمن بيئة  Tkinter لواجهة المستخدم الرسومية GUI  ويتيح للمستخدمين تشفير وفك تشفير الملفات باستخدام كلمة مرور يتم توليد مفتاح تشفير قوي بناءً عليها.

**المزايا:**

تشفير الملفات باستخدام AES مع  salt و  IV لتحسين الأمان - إدارة الملفات عبر واجهة رسومية سهلة الاستخدام - دعم التشفير وفك التشفير باستخدام كلمة مرور- تسجيل السجلات لجميع العمليات لمراجعتها بسهولة بالوقت والتاريخ لكل يوم - التفاعل مع المستخدم عبر رسائل خطأ ناجحة أو فاشلة.

**الخصائص الوظفية**

اختيار الملفات: إمكانية تحديد الملفات التي سيتم تشفيرها أو فك تشفيرها. إدخال كلمة المرور: يجب إدخال كلمة مرور لتوليد مفتاح التشفير (ويتم التحقق منها باستخدام. PBKDF2  تشفير الملفات: التطبيق يقوم بتشفير الملف باستخدام خوارزمية AES مع IV و  salt . فك تشفير الملفات: يمكن فك تشفير الملفات المشفرة بالتنسيق .ebaha باستخدام نفس كلمة المرور. واجهة مستخدم رسومية: تحتوي على أزرار تشفير و فك التشفير وأدوات التصفح لاختيار الملفات.سجل الأخطاء والأنشطة: يمكن متابعة حالة التشفير والفك في واجهة المستخدم مع السجلات.

**الاثر**

تحسين الأمان: باستخدام خوارزمية AES القوية مع salt و IV، يصبح الملف مشفرًا بشكل صعب الاختراق. سهولة الاستخدام: توفر الواجهة الرسومية Tkinter تجربة مستخدم مريحة، مما يجعل التطبيق سهل الاستخدام للمبتدئين. التوثيق: يتيح التسجيل اللوجي متابعة جميع العمليات وفحص أي أخطاء أو نجاحات. الامتثال: يمكن استخدامه في سياقات حيث يجب حماية البيانات الشخصية أو الحساسة.

**الميزات الأمنية المستخدمة**

**1. تشفير AES**

يستخدم تطبيق التشفير خوارزمية AES، وهي واحدة من أكثر خوارزميات التشفير أمانًا. يتم استخدام وضع CBC (Cipher Block Chaining) والذي يوفر حماية إضافية ضد بعض أنواع الهجمات.

**2. توليد المفاتيح باستخدام PBKDF2**


يتم استخدام وظيفة KDF (Key Derivation Function) PBKDF2HMAC لتوليد مفتاح من كلمة المرور. هذا يساعد على تقوية كلمة المرور ضد هجمات القوة الغاشمة من خلال زيادة عدد التكرارات (100000 في هذا التطبيق).

**3. استخدام الملح (Salt)**

يتم توليد ملح عشوائي (32 بايت) لكل عملية تشفير، مما يمنع الهجمات التي تعتمد على جداول قوس قزح. يتم تضمين الملح في الملف المشفر لإعادة استخدامه أثناء فك التشفير.

**4. تشفير البيانات في كتل**

يتم قراءة الملفات وتشفيرها في كتل (chunks) بحجم 64 كيلوبايت. هذا يقلل من استخدام الذاكرة ويساعد في معالجة الملفات الكبيرة بشكل أكثر كفاءة.

**5. التحقق من صحة المدخلات**

يتضمن التطبيق عمليات التحقق من صحة المدخلات للتأكد من أن المستخدم قد أدخل ملفًا وكلمة مرور صحيحة، مما يقلل من الأخطاء المحتملة.

**6. التعامل مع الأخطاء**

يحتوي التطبيق على نظام مركزي للتعامل مع الأخطاء، حيث يتم تسجيل الأخطاء وعرض رسائل واضحة للمستخدم، مما يعزز تجربة المستخدم.

**7. سجل الأحداث**

يتم تسجيل جميع الأحداث المهمة، مثل نجاح عمليات التشفير وفك التشفير، في ملف سجل. هذا يساعد في تتبع الأنشطة ويعزز الأمان عن طريق توفير معلومات مفيدة في حالة حدوث مشاكل.

**8. واجهة مستخدم بسيطة وسهلة الاستخدام**

تم تصميم واجهة المستخدم لتكون بديهية، مما يسهل على المستخدمين الجدد استخدام التطبيق دون الحاجة إلى معرفة تقنية متقدمة.

**في الكود المقدم، يتم استخدام ترخيص Gnu General Public License الإصدار 2 (GPLv2). هذا الترخيص يتيح للمستخدمين:**


   استخدام البرنامج لأي غرض، بما في ذلك الأغراض التجارية.
تعديل الكود: يسمح للمستخدمين بتعديل الكود البرمجي ليتناسب مع احتياجاتهم، بشرط أن يتم توزيع النسخ المعدلة تحت نفس الترخيص.
توزيع البرنامج: يمكن توزيع البرنامج، سواء كان في نسخته الأصلية أو المعدلة، مع الالتزام بشروط الترخيص.
الشفافية: يشجع الترخيص على توفير الكود المصدري للمستخدمين، مما يعزز الشفافية والثقة.
