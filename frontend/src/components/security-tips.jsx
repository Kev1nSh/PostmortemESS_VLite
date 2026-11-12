import { useState } from "react";

const securityTips = [
  {
    category: "Social engineering",
    title: "Det börjar ofta med en berättelse",
    description:
      "Ett phishingmejl kan börja med ett trovärdigt scenario. Någon utger sig för att vara IT-support, en chef eller en kollega och ber dig utföra en enkel åtgärd. Kontrollera alltid vem som faktiskt kontaktar dig innan du agerar.",
  },
  {
    category: "Social engineering",
    title: "Var uppmärksam på känslomässig press",
    description:
      "Bedragare spelar ofta på rädsla, brådska, nyfikenhet eller hjälpsamhet. Ett mejl som försöker stressa dig att klicka, logga in eller lämna information bör granskas extra noggrant.",
  },
  {
    category: "Phishing",
    title: "Kontrollera avsändaradressen",
    description:
      "Granska hela e-postadressen, inte bara visningsnamnet. Bedragare kan använda adresser som liknar riktiga företagsadresser.",
  },
  {
    category: "Social engineering",
    title: "Var uppmärksam på brådskande mejl",
    description:
      "Mejl som hotar med att stänga ditt konto eller kräver omedelbar åtgärd kan vara phishing. Stanna upp och verifiera informationen innan du agerar.",
  },
  {
    category: "Domäner",
    title: "Se upp för falska domäner",
    description:
      "Bedragare kan byta ut bokstäver mot liknande tecken, exempelvis använda siffran 0 i stället för bokstaven o. Kontrollera hela domännamnet noggrant.",
  },
  {
    category: "Länkar",
    title: "Kontrollera den verkliga länkdestinationen",
    description:
      "Den synliga texten i ett mejl behöver inte motsvara den verkliga webbadressen. Håll muspekaren över länken och kontrollera vart den leder innan du klickar.",
  },
  {
    category: "AI och phishing",
    title: "AI gör phishingmejl mer trovärdiga",
    description:
      "Bedragare kan använda AI för att skapa välskrivna och personligt anpassade mejl. Stavfel och dålig grammatik är inte längre tillförlitliga varningssignaler. Fokusera på vad mejlet ber dig att göra.",
  },
  {
    category: "Bilagor",
    title: "Öppna inte oväntade bilagor",
    description:
      "Öppna inte oväntade filer bara för att de verkar komma från en bekant avsändare. Verifiera först att bilagan är väntad.",
  },
  {
    category: "Bilagor",
    title: "Kontrollera filens verkliga format",
    description:
      "En fil kan ha ett vilseledande namn, exempelvis dokument.pdf.exe. Kontrollera filändelsen och var extra försiktig med oväntade filer.",
  },
  {
    category: "Makroattacker",
    title: "Aktivera inte makron på uppmaning",
    description:
      "Ett Word- eller Excel-dokument kan uppmana dig att aktivera makron för att visa innehållet. Makron kan användas för att köra skadlig kod.",
  },
  {
    category: "Identitetsbedrägeri",
    title: "Verifiera ovanliga förfrågningar",
    description:
      "Bekräfta betalningar, lösenordsförfrågningar och känsliga instruktioner via en separat, betrodd kommunikationskanal.",
  },
  {
    category: "E-postkonversationer",
    title: "Var uppmärksam på kapade mejltrådar",
    description:
      "Angripare kan ta över en befintlig e-postkonversation och skicka nya länkar eller bilagor. Var extra uppmärksam på oväntade ändringar i en pågående konversation.",
  },
  {
    category: "E-postautentisering",
    title: "Kontrollera SPF, DKIM och DMARC",
    description:
      "Dessa kontroller hjälper till att verifiera e-postens autenticitet. Saknade eller misslyckade kontroller kan vara varningssignaler, men innebär inte automatiskt att mejlet är skadligt.",
  },
  {
    category: "Reply-To",
    title: "Kontrollera Reply-To-adressen",
    description:
      "Ett mejl kan komma från en till synes legitim avsändare men ha en annan Reply-To-adress. Kontrollera vart ditt svar faktiskt skickas innan du svarar.",
  },
  {
    category: "Falska dokument",
    title: "Var försiktig med delade dokument",
    description:
      "Bedragare kan skicka länkar till falska dokument som efterliknar exempelvis Microsoft 365 eller SharePoint. Kontrollera webbadressen innan du loggar in.",
  },
  {
    category: "QR-phishing",
    title: "Var försiktig med QR-koder i mejl",
    description:
      "En QR-kod kan dölja den verkliga webbadressen och leda till en falsk inloggningssida. Kontrollera alltid vart QR-koden leder innan du loggar in eller lämnar information.",
  },
  {
    category: "Mobil phishing",
    title: "Var extra försiktig på mobilen",
    description:
      "På en smartphone kan det vara svårare att se hela webbadressen. Tryck och håll på länken för att förhandsgranska destinationen innan du öppnar den.",
  },
  {
    category: "Säker hantering",
    title: "Använd STAR när du är osäker",
    description:
      "Stop. Stanna – skynda inte. Think. Tänk – verkar mejlet normalt och förväntat? Ask. Fråga – verifiera via en annan kanal. React. Reagera – rapportera mejlet om något verkar misstänkt.",
  },
  {
    category: "Domäner",
    title: "Se upp för Punycode-domäner",
    description:
      "En phishinglänk kan använda Punycode för att skapa ett domännamn som ser ut som en välkänd webbplats. Kontrollera länken noggrant och var extra uppmärksam om den verkliga adressen innehåller `xn--`.",
  },
];

function SecurityTips() {
  const [tipIndex, setTipIndex] = useState(() =>
    Math.floor(Math.random() * securityTips.length),
  );

  const showNextTip = () => {
    setTipIndex((currentIndex) => {
      const offset =
        1 + Math.floor(Math.random() * (securityTips.length - 1));

      return (currentIndex + offset) % securityTips.length;
    });
  };

  const currentTip = securityTips[tipIndex];

  return (
    <div className="security-tips">
      <div className="security-tips-header">
        <h3>Säkerhetstips</h3>
      </div>

      <span className="security-tip-category">
        {currentTip.category}
      </span>

      <h4 className="security-tip-title">
        {currentTip.title}
      </h4>

      <p className="security-tip-description">
        {currentTip.description}
      </p>

      <button
        type="button"
        className="security-tip-button"
        onClick={showNextTip}
      >
        Visa ett annat tips
      </button>
    </div>
  );
}

export default SecurityTips;